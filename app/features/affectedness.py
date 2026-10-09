"""Version-aware affectedness matching between asset software and CVEs.

A CVE names vulnerable products as CPE match criteria, usually with a version
range (``versionStartIncluding`` … ``versionEndExcluding``). Matching on
vendor and product alone marks every installed version as affected, so a
patched component is still reported. This module compares the installed
version against the stored NVD ranges and reports one of:

- ``version``       installed version lies inside a vulnerable range
- ``product_only``  product matches but the installed version is unknown, or
                    the CVE carries no usable range (treated as affected)
- ``not_in_range``  product matches and the installed version is outside every
                    vulnerable range (treated as not affected)
- ``none``          no vendor/product match

VEX statements are applied only when they are scoped to the asset or name a
component that is actually installed on it, so a statement about one product
can never suppress a finding for a different product.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

MATCH_VERSION = "version"
MATCH_PRODUCT_ONLY = "product_only"
MATCH_NOT_IN_RANGE = "not_in_range"
MATCH_NONE = "none"

_ANY = {"*", "-", "", None}


def norm(name: Optional[str]) -> str:
    """Normalise a vendor/product token (CPE uses underscores, NVD text uses spaces)."""
    return re.sub(r"[\s_]+", "_", (name or "").strip().lower())


def upstream_version(version: str) -> str:
    """Reduce a packaged version to the upstream release it carries.

    Drops a Debian epoch (``1:``), a leading tag such as ``v`` or ``go``, and the
    distribution revision (``-1~deb12u1``, ``-r2``, ``+dfsg``), so that
    ``3.0.15-1~deb12u1`` compares as ``3.0.15`` against NVD's upstream ranges.
    """
    v = (version or "").strip().replace("\\", "")
    if ":" in v and v.split(":", 1)[0].isdigit():
        v = v.split(":", 1)[1]
    v = re.sub(r"^[^\d]+", "", v)
    return re.split(r"[-~+_ ]", v, maxsplit=1)[0]


def version_key(version: str) -> Tuple[Tuple[int, Any], ...]:
    """Loose, total ordering for version strings such as 2.14.1, 7.4.2 or 1.1.1k."""
    parts = re.findall(r"\d+|[a-zA-Z]+", upstream_version(version))
    return tuple((0, int(p)) if p.isdigit() else (1, p.lower()) for p in parts)


def parse_cpe(cpe: Optional[str]) -> Optional[Dict[str, str]]:
    """Return vendor/product/version from a CPE 2.3 string, or None."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    return {"vendor": norm(parts[3]), "product": norm(parts[4]), "version": parts[5]}


@dataclass(frozen=True)
class VulnerableRange:
    vendor: str
    product: str
    exact: Optional[str] = None          # single vulnerable version
    start_incl: Optional[str] = None
    start_excl: Optional[str] = None
    end_incl: Optional[str] = None
    end_excl: Optional[str] = None

    @property
    def all_versions(self) -> bool:
        return not any((self.exact, self.start_incl, self.start_excl, self.end_incl, self.end_excl))

    def contains(self, version: str) -> bool:
        if self.all_versions:
            return True
        key = version_key(version)
        if self.exact is not None:
            return key == version_key(self.exact)
        if self.start_incl is not None and key < version_key(self.start_incl):
            return False
        if self.start_excl is not None and key <= version_key(self.start_excl):
            return False
        if self.end_incl is not None and key > version_key(self.end_incl):
            return False
        if self.end_excl is not None and key >= version_key(self.end_excl):
            return False
        return True

    def describe(self) -> str:
        if self.all_versions:
            return "all versions"
        if self.exact is not None:
            return f"= {self.exact}"
        bounds = []
        if self.start_incl is not None:
            bounds.append(f">= {self.start_incl}")
        if self.start_excl is not None:
            bounds.append(f"> {self.start_excl}")
        if self.end_incl is not None:
            bounds.append(f"<= {self.end_incl}")
        if self.end_excl is not None:
            bounds.append(f"< {self.end_excl}")
        return ", ".join(bounds)


def vulnerable_ranges(vuln: Any) -> List[VulnerableRange]:
    """Extract vulnerable (vendor, product, version-range) entries for a CVE.

    Uses the stored raw NVD configurations when present, since they keep the
    version bounds; otherwise falls back to the flattened affected-products list.
    """
    ranges: List[VulnerableRange] = []
    raw = getattr(vuln, "raw_source_json", None) or {}
    for config in raw.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable", False):
                    continue
                cpe = parse_cpe(m.get("criteria"))
                if not cpe:
                    continue
                bounded = any(
                    m.get(k) for k in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding",
                    )
                )
                ranges.append(VulnerableRange(
                    vendor=cpe["vendor"],
                    product=cpe["product"],
                    exact=None if bounded or cpe["version"] in _ANY else cpe["version"],
                    start_incl=m.get("versionStartIncluding"),
                    start_excl=m.get("versionStartExcluding"),
                    end_incl=m.get("versionEndIncluding"),
                    end_excl=m.get("versionEndExcluding"),
                ))
    if ranges:
        return ranges

    for p in getattr(vuln, "affected_products_json", None) or []:
        if isinstance(p, dict):
            vendor, product, version = norm(p.get("vendor")), norm(p.get("product")), p.get("version")
        elif isinstance(p, str):
            cpe = parse_cpe(p)
            if not cpe:
                continue
            vendor, product, version = cpe["vendor"], cpe["product"], cpe["version"]
        else:
            continue
        if vendor and product:
            ranges.append(VulnerableRange(
                vendor=vendor, product=product,
                exact=None if version in _ANY or version == "all" else version,
            ))
    return ranges


def component_identity(sw: Any) -> Tuple[str, str, Optional[str]]:
    """(vendor, product, version) for an installed component, preferring its CPE."""
    cpe = parse_cpe(getattr(sw, "cpe", None))
    version = getattr(sw, "version", None)
    if cpe:
        cpe_version = None if cpe["version"] in _ANY else cpe["version"]
        return cpe["vendor"], cpe["product"], version or cpe_version
    return norm(getattr(sw, "vendor", None)), norm(getattr(sw, "product", None)), version


def match_component(sw: Any, ranges: Iterable[VulnerableRange]) -> Dict[str, Any]:
    """Compare one installed component with a CVE's vulnerable ranges."""
    vendor, product, version = component_identity(sw)
    candidates = [r for r in ranges if r.vendor == vendor and r.product == product]
    if not candidates:
        return {"level": MATCH_NONE}

    base = {"vendor": vendor, "product": product, "installed_version": version,
            "purl": getattr(sw, "purl", None)}
    if not version:
        return {**base, "level": MATCH_PRODUCT_ONLY,
                "detail": "product matches; installed version unknown"}
    for r in candidates:
        if r.contains(version):
            if r.all_versions:
                return {**base, "level": MATCH_PRODUCT_ONLY,
                        "detail": "product matches; the CVE lists no version bound"}
            return {**base, "level": MATCH_VERSION, "vulnerable_range": r.describe(),
                    "detail": f"installed {version} is within vulnerable range ({r.describe()})"}
    return {**base, "level": MATCH_NOT_IN_RANGE,
            "detail": f"installed {version} is outside every vulnerable range"}


def best_match(components: Iterable[Any], vuln: Any) -> Dict[str, Any]:
    """Strongest evidence across an asset's components for one CVE."""
    ranges = vulnerable_ranges(vuln)
    if not ranges:
        return {"level": MATCH_NONE}
    order = {MATCH_VERSION: 3, MATCH_PRODUCT_ONLY: 2, MATCH_NOT_IN_RANGE: 1, MATCH_NONE: 0}
    best: Dict[str, Any] = {"level": MATCH_NONE}
    for sw in components:
        m = match_component(sw, ranges)
        if order[m["level"]] > order[best["level"]]:
            best = m
            if m["level"] == MATCH_VERSION:
                break
    return best


def _purl_base(purl: Optional[str]) -> str:
    """PURL without version, qualifiers or subpath, lower-cased."""
    if not purl:
        return ""
    return re.split(r"[@?#]", purl.strip().lower(), maxsplit=1)[0]


def vex_applies(vex: Any, asset_id: Any, components: Iterable[Any]) -> bool:
    """Whether a VEX statement may be applied to this asset.

    It applies when it is scoped to the asset, or when it is unscoped and names
    a product that is installed on the asset (by PURL, CPE or product name).
    """
    vex_asset = getattr(vex, "asset_id", None)
    if vex_asset is not None:
        return vex_asset == asset_id

    product_ref = (getattr(vex, "product", "") or "").strip().lower()
    if not product_ref or product_ref == "unknown":
        return False
    ref_cpe = parse_cpe(product_ref)
    ref_purl = _purl_base(product_ref) if product_ref.startswith("pkg:") else ""
    vex_vendor = norm(getattr(vex, "vendor", None))

    for sw in components:
        vendor, product, _ = component_identity(sw)
        if ref_cpe and (ref_cpe["vendor"], ref_cpe["product"]) == (vendor, product):
            return True
        if ref_purl and ref_purl == _purl_base(getattr(sw, "purl", None)):
            return True
        if not ref_cpe and not ref_purl and norm(product_ref) == product:
            if vex_vendor in ("", "unknown") or vex_vendor == vendor:
                return True
    return False
