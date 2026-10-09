"""SBOM / VEX ingestion provider.

Supports:
- CycloneDX JSON (v1.4, v1.5, v1.6)
- Simplified SPDX JSON
- OpenVEX JSON
- Manual CSV import

Accepts SBOMs as produced by Syft, Trivy or cdxgen. Components are resolved to
an NVD vendor/product identity (from their CPE, or from the package name when
it maps to exactly one known vendor) so they can be matched against CVE
configurations by `app.features.affectedness`.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.asset_models import Asset, AssetSoftwareObs, VexStatementObs
from app.db.models import Vulnerability
from app.schemas.asset_schemas import SBOMImport, SoftwareComponent, VexImport, VexStatement

log = get_logger(__name__)


# ── Component identity resolution ──────────────────────────────────────

_known_products: Optional[Dict[str, Set[str]]] = None


def known_products(session: Session) -> Dict[str, Set[str]]:
    """Map of NVD product name → vendors that publish it, built from the CVE corpus."""
    global _known_products
    if _known_products is None:
        from sqlalchemy import text as sa_text

        from app.features.affectedness import norm

        rows = session.execute(sa_text(
            "SELECT DISTINCT lower(p->>'vendor'), lower(p->>'product') "
            "FROM vulnerability, jsonb_array_elements(affected_products_json) p "
            "WHERE jsonb_typeof(affected_products_json) = 'array'"
        )).all()
        index: Dict[str, Set[str]] = {}
        for vendor, product in rows:
            if vendor and product:
                index.setdefault(norm(product), set()).add(norm(vendor))
        _known_products = index
    return _known_products


def _purl_parts(purl: Optional[str]) -> Tuple[str, str]:
    """(namespace, name) from a Package URL such as pkg:maven/org.apache/log4j-core@2.14.1."""
    if not purl or not purl.startswith("pkg:"):
        return "", ""
    body = purl[4:].split("@", 1)[0].split("?", 1)[0].split("#", 1)[0]
    segments = [seg for seg in body.split("/") if seg]
    if len(segments) < 2:
        return "", ""
    return "/".join(segments[1:-1]), segments[-1]


def resolve_identity(
    comp: SoftwareComponent,
    cpe_candidates: List[str],
    products: Dict[str, Set[str]],
) -> Tuple[SoftwareComponent, float]:
    """Attach the best NVD vendor/product identity to a component.

    Returns the component and a confidence: 1.0 for a CPE whose vendor/product
    is known to NVD, 0.8 for an unverified CPE, 0.6 when the package name maps
    to exactly one NVD vendor, 0.3 when no identity could be established.
    """
    from app.features.affectedness import norm, parse_cpe

    parsed = [(c, parse_cpe(c)) for c in cpe_candidates]
    parsed = [(c, d) for c, d in parsed if d]
    for cpe, d in parsed:
        if d["vendor"] in products.get(d["product"], set()):
            return comp.model_copy(update={
                "cpe": cpe, "vendor": d["vendor"], "product": d["product"]}), 1.0
    if parsed:
        cpe, d = parsed[0]
        return comp.model_copy(update={
            "cpe": cpe, "vendor": d["vendor"], "product": d["product"]}), 0.8

    _, purl_name = _purl_parts(comp.purl)
    for name in (norm(comp.product), norm(purl_name)):
        vendors = products.get(name, set())
        if name and len(vendors) == 1:
            return comp.model_copy(update={
                "vendor": next(iter(vendors)), "product": name}), 0.6
    return comp, 0.3


# ── SBOM Ingestion ─────────────────────────────────────────────────────

def detect_sbom_format(data: Dict[str, Any]) -> str:
    if str(data.get("bomFormat", "")).lower() == "cyclonedx" or "components" in data:
        return "cyclonedx"
    if "spdxVersion" in data or "packages" in data:
        return "spdx"
    raise ValueError("Unrecognised SBOM: expected CycloneDX or SPDX JSON")


def ingest_sbom_data(
    data: Dict[str, Any],
    asset_id: UUID,
    session: Session,
    *,
    format: Optional[str] = None,
    replace: bool = True,
) -> Dict[str, Any]:
    """Store an SBOM document as the software inventory of an asset.

    With ``replace`` (default) the asset's previously imported SBOM components
    are superseded, so the inventory reflects the latest document.
    """
    asset = session.query(Asset).filter_by(id=asset_id).first()
    if not asset:
        raise ValueError(f"Asset {asset_id} not found")

    fmt = format or detect_sbom_format(data)
    if fmt == "cyclonedx":
        parsed = _parse_cyclonedx(data)
    elif fmt == "spdx":
        parsed = _parse_spdx(data)
    else:
        raise ValueError(f"Unsupported SBOM format: {fmt}")

    products = known_products(session)
    if replace:
        session.query(AssetSoftwareObs).filter(
            AssetSoftwareObs.asset_id == asset_id,
            AssetSoftwareObs.source.in_(["cyclonedx", "spdx"]),
        ).delete(synchronize_session=False)

    now = datetime.utcnow()
    resolved = 0
    for comp, candidates in parsed:
        comp, confidence = resolve_identity(comp, candidates, products)
        if confidence >= 0.6:
            resolved += 1
        session.add(AssetSoftwareObs(
            asset_id=asset_id,
            vendor=(comp.vendor or "unknown")[:128],
            product=(comp.product or "unknown")[:128],
            version=(comp.version or None) and comp.version[:64],
            cpe=(comp.cpe or None) and comp.cpe[:256],
            purl=(comp.purl or None) and comp.purl[:512],
            install_path=comp.install_path,
            observed_at=now,
            confidence=confidence,
            source=comp.source,
        ))

    session.commit()
    summary = {"components": len(parsed), "identity_resolved": resolved, "format": fmt}
    log.info("sbom_ingested", asset_id=str(asset_id), **summary)
    return summary


def ingest_sbom_file(
    path: str,
    asset_id: UUID,
    session: Session,
    *,
    format: Optional[str] = None,
) -> int:
    """Parse an SBOM file and store its components for an asset."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"SBOM file not found: {path}")
    with open(file_path) as f:
        data = json.load(f)
    return ingest_sbom_data(data, asset_id, session, format=format)["components"]


def _parse_cyclonedx(data: Dict[str, Any]) -> List[Tuple[SoftwareComponent, List[str]]]:
    """Parse CycloneDX JSON into components with their candidate CPEs."""
    out: List[Tuple[SoftwareComponent, List[str]]] = []

    def walk(components: List[Dict[str, Any]]) -> None:
        for comp in components or []:
            if comp.get("type") == "file":
                continue  # file entries are not installable software
            supplier = comp.get("supplier") or {}
            vendor = (
                comp.get("group") or comp.get("publisher")
                or (supplier.get("name") if isinstance(supplier, dict) else None)
                or "unknown"
            )
            candidates: List[str] = []
            if comp.get("cpe"):
                candidates.append(comp["cpe"])
            for prop in comp.get("properties", []) or []:
                if prop.get("name") in ("cpe", "syft:cpe23") and prop.get("value"):
                    candidates.append(prop["value"])
            out.append((SoftwareComponent(
                vendor=str(vendor),
                product=str(comp.get("name", "unknown")),
                version=comp.get("version"),
                cpe=candidates[0] if candidates else None,
                purl=comp.get("purl"),
                source="cyclonedx",
            ), candidates))
            walk(comp.get("components", []))

    walk(data.get("components", []))
    return out


def _parse_spdx(data: Dict[str, Any]) -> List[Tuple[SoftwareComponent, List[str]]]:
    """Parse SPDX JSON into components with their candidate CPEs."""
    out: List[Tuple[SoftwareComponent, List[str]]] = []
    for pkg in data.get("packages", []) or []:
        vendor = pkg.get("supplier") or pkg.get("originator") or "unknown"
        vendor = str(vendor).replace("Organization:", "").replace("Person:", "").strip()
        candidates: List[str] = []
        purl = None
        for ref in pkg.get("externalRefs", []) or []:
            if ref.get("referenceType") == "cpe23Type" and ref.get("referenceLocator"):
                candidates.append(ref["referenceLocator"])
            elif ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
        out.append((SoftwareComponent(
            vendor=vendor or "unknown",
            product=str(pkg.get("name", "unknown")),
            version=pkg.get("versionInfo"),
            cpe=candidates[0] if candidates else None,
            purl=purl,
            source="spdx",
        ), candidates))
    return out


# ── VEX Ingestion ──────────────────────────────────────────────────────

def detect_vex_format(data: Dict[str, Any]) -> str:
    if "statements" in data:
        return "openvex"
    if "vulnerabilities" in data and "document" in data:
        return "csaf_vex"
    raise ValueError("Unrecognised VEX document: expected OpenVEX or CSAF VEX JSON")


def ingest_vex_data(
    data: Dict[str, Any],
    session: Session,
    *,
    format: Optional[str] = None,
    asset_id: Optional[UUID] = None,
) -> Dict[str, Any]:
    """Store VEX statements.

    When ``asset_id`` is given the statements are scoped to that asset. Unscoped
    statements are applied only to assets that have the named product installed.
    """
    fmt = format or detect_vex_format(data)
    if fmt == "openvex":
        statements = _parse_openvex(data)
    elif fmt == "csaf_vex":
        statements = _parse_csaf_vex(data)
    else:
        raise ValueError(f"Unsupported VEX format: {fmt}")

    if asset_id is not None and not session.query(Asset).filter_by(id=asset_id).first():
        raise ValueError(f"Asset {asset_id} not found")

    inserted, unknown_cves = 0, []
    now = datetime.utcnow()
    for stmt in statements:
        vuln = session.query(Vulnerability).filter_by(cve_id=stmt.cve_id).first()
        if not vuln:
            unknown_cves.append(stmt.cve_id)
            continue
        session.add(VexStatementObs(
            vulnerability_id=vuln.id,
            asset_id=asset_id,
            vendor=(stmt.vendor or "unknown")[:128],
            product=(stmt.product or "unknown")[:128],
            status=stmt.status.value if hasattr(stmt.status, "value") else stmt.status,
            justification=(
                stmt.justification.value
                if stmt.justification and hasattr(stmt.justification, "value")
                else stmt.justification
            ),
            impact_statement=stmt.impact_statement,
            action_statement=stmt.action_statement,
            observed_at=now,
            source=stmt.source,
        ))
        inserted += 1

    session.commit()
    summary = {
        "statements": inserted,
        "skipped_unknown_cves": sorted(set(unknown_cves)),
        "format": fmt,
        "scope": "asset" if asset_id else "product",
    }
    log.info("vex_ingested", **{k: v for k, v in summary.items() if k != "skipped_unknown_cves"})
    return summary


def ingest_vex_file(
    path: str,
    session: Session,
    *,
    format: Optional[str] = None,
    asset_id: Optional[UUID] = None,
) -> int:
    """Parse a VEX file and store its statements."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"VEX file not found: {path}")
    with open(file_path) as f:
        data = json.load(f)
    return ingest_vex_data(data, session, format=format, asset_id=asset_id)["statements"]


def _parse_openvex(data: Dict[str, Any]) -> List[VexStatement]:
    """Parse OpenVEX JSON."""
    statements: List[VexStatement] = []

    for stmt in data.get("statements", []) or []:
        vulnerability = stmt.get("vulnerability", "")
        if isinstance(vulnerability, dict):
            vuln_id = vulnerability.get("name") or vulnerability.get("@id") or ""
        else:
            vuln_id = str(vulnerability)
        vuln_id = vuln_id.rsplit("/", 1)[-1]
        if not vuln_id.upper().startswith("CVE-"):
            continue

        for product in stmt.get("products", []) or []:
            if isinstance(product, str):
                product_id = product
            else:
                identifiers = product.get("identifiers") or {}
                product_id = (
                    identifiers.get("purl") or identifiers.get("cpe23")
                    or product.get("@id") or "unknown"
                )
            statements.append(VexStatement(
                cve_id=vuln_id.upper(),
                vendor="unknown",
                product=product_id,
                status=stmt.get("status", "under_investigation"),
                justification=stmt.get("justification"),
                impact_statement=stmt.get("impact_statement"),
                action_statement=stmt.get("action_statement"),
                source="openvex",
            ))

    return statements


def _parse_csaf_vex(data: Dict[str, Any]) -> List[VexStatement]:
    """Parse CSAF VEX JSON (product names resolved from the product tree)."""
    names: Dict[str, str] = {}

    def collect(branches: List[Dict[str, Any]]) -> None:
        for br in branches or []:
            prod = br.get("product")
            if prod and prod.get("product_id"):
                helper = prod.get("product_identification_helper") or {}
                names[prod["product_id"]] = (
                    helper.get("purl") or helper.get("cpe") or prod.get("name") or prod["product_id"]
                )
            collect(br.get("branches", []))

    tree = data.get("product_tree", {}) or {}
    collect(tree.get("branches", []))
    for prod in tree.get("full_product_names", []) or []:
        if prod.get("product_id"):
            names.setdefault(prod["product_id"], prod.get("name") or prod["product_id"])

    status_map = {
        "known_not_affected": "not_affected",
        "known_affected": "affected",
        "fixed": "fixed",
        "under_investigation": "under_investigation",
    }
    statements: List[VexStatement] = []
    for vuln in data.get("vulnerabilities", []) or []:
        cve_id = vuln.get("cve")
        if not cve_id:
            continue
        for status_type, product_ids in (vuln.get("product_status", {}) or {}).items():
            if status_type not in status_map:
                continue
            for pid in (product_ids if isinstance(product_ids, list) else [product_ids]):
                statements.append(VexStatement(
                    cve_id=cve_id,
                    vendor="unknown",
                    product=str(names.get(pid, pid)),
                    status=status_map[status_type],
                    source="csaf_vex",
                ))
    return statements


# ── Affectedness Matching ──────────────────────────────────────────────

def check_affectedness(
    asset_id: UUID,
    cve_id: str,
    session: Session,
) -> Dict[str, Any]:
    """Affectedness of an asset for a CVE, using the decision engine's own logic."""
    from app.features.policy_engine import _resolve_affectedness

    vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
    if not vuln:
        return {"status": "unknown", "reason": f"CVE {cve_id} not found in database"}
    asset = session.query(Asset).filter_by(id=asset_id).first()
    if not asset:
        return {"status": "unknown", "reason": f"Asset {asset_id} not found"}

    status, tag, detail = _resolve_affectedness(asset, vuln, session, datetime.utcnow().date())
    return {
        "status": getattr(status, "value", status),
        "evidence": tag,
        "reason": detail or "No VEX statement or SBOM component matches this CVE",
    }


# ── Synthetic data generation (for testing) ───────────────────────────

def generate_synthetic_sbom(
    asset_id: UUID,
    num_components: int = 50,
) -> SBOMImport:
    """Generate a synthetic SBOM for testing purposes.

    Creates a realistic mix of common server software.
    """
    import random

    common_software = [
        ("apache", "httpd", "2.4.57"),
        ("apache", "log4j", "2.17.1"),
        ("apache", "tomcat", "10.1.18"),
        ("apache", "struts", "6.3.0"),
        ("openssl", "openssl", "3.2.1"),
        ("linux", "linux_kernel", "6.7.5"),
        ("microsoft", "exchange_server", "2019"),
        ("microsoft", ".net_framework", "4.8.1"),
        ("oracle", "java_se", "21.0.2"),
        ("oracle", "mysql", "8.0.36"),
        ("postgresql", "postgresql", "16.2"),
        ("redis", "redis", "7.2.4"),
        ("nginx", "nginx", "1.25.4"),
        ("docker", "docker_engine", "25.0.3"),
        ("kubernetes", "kubernetes", "1.29.2"),
        ("python", "python", "3.12.2"),
        ("nodejs", "node.js", "20.11.1"),
        ("fortinet", "fortigate", "7.4.3"),
        ("paloaltonetworks", "pan-os", "11.1.2"),
        ("cisco", "ios_xe", "17.12.1"),
    ]

    selected = random.sample(
        common_software,
        min(num_components, len(common_software)),
    )

    components = [
        SoftwareComponent(
            vendor=vendor,
            product=product,
            version=version,
            source="synthetic",
        )
        for vendor, product, version in selected
    ]

    return SBOMImport(
        asset_id=asset_id,
        format="cyclonedx",
        components=components,
        tool="synthetic_generator",
    )
