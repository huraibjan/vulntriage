"""Opt-in distribution-backport check against OSV for SBOM findings.

``app.features.affectedness`` compares the upstream part of an installed
version with NVD ranges, so a Debian or Alpine package that carries a
backported fix (``openssl 3.0.15-1~deb12u1``) can still be reported as
affected. OSV (https://api.osv.dev) republishes the distribution security
trackers, keyed by source package and distribution release, and therefore
knows which CVEs a given package revision is still exposed to.

The check is deliberately conservative, because a wrong "fixed" verdict hides
a real finding:

- ``confirmed_by_distro``  the distribution lists the CVE as affecting the
                           installed package revision
- ``fixed_by_distro``      the distribution tracks the CVE for this package
                           and release, and the installed revision is outside
                           the affected set
- ``no_distro_data``       everything else, including every failure mode

OSV answers an unknown package, an unknown release and a fully patched package
with the same empty result, so an empty answer alone is never read as fixed. A
second, version-less query establishes which CVEs the distribution tracks for
the package; only a CVE in that tracked set can be reported as fixed.

Nothing in the application calls this module by default. Enabling it sends
package names, versions and distribution releases to a third-party service.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, quote, unquote

from app.core.logging import get_logger

logger = get_logger(__name__)

OSV_API_URL = "https://api.osv.dev"

CONFIRMED_BY_DISTRO = "confirmed_by_distro"
FIXED_BY_DISTRO = "fixed_by_distro"
NO_DISTRO_DATA = "no_distro_data"

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_REQUESTS = 40
# OSV accepts up to 1000 queries per batch; a smaller chunk limits what a
# single failed request can invalidate.
_BATCH_SIZE = 250

PackageKey = Tuple[str, str, str]  # (OSV ecosystem, source package, version)
HttpPost = Callable[[str, Dict[str, Any], float], Any]
HttpGet = Callable[[str, float], Any]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Tracker records are named after the CVE they describe (DEBIAN-CVE-2024-13176,
# ALPINE-CVE-2026-22184), so they resolve without a further request.
_DIRECT_ID_RE = re.compile(r"^(?:[A-Z]+-)?(CVE-\d{4}-\d{4,})$", re.IGNORECASE)
_ALIAS_FIELDS = ("aliases", "upstream", "related")

# OSV does not reject a version it cannot parse; it answers with the advisories
# that have no fixed version, which reads as "newer than every fix". A version
# outside the ecosystem grammar is therefore never sent. Both patterns are
# stricter than the distribution policies (no colon outside the epoch, no empty
# revision), because rejecting a valid version only costs a no_distro_data.
_DEBIAN_VERSION_RE = re.compile(r"(?:\d+:)?\d[A-Za-z0-9.+~]*(?:-[A-Za-z0-9.+~]+)*")
_ALPINE_VERSION_RE = re.compile(
    r"\d+(?:\.\d+)*[a-z]?(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*-r\d+"
)
_ECOSYSTEM_RE = re.compile(r"(?:(Debian):\d+|(Alpine):v\d+\.\d+)")


class OsvResult(Dict[PackageKey, Set[str]]):
    """CVE ids OSV reports for each package revision, plus what the distribution tracks.

    A key is present only when OSV demonstrably holds advisories for that
    ecosystem and package and the affected set was retrieved completely.
    ``tracked`` holds the CVEs the distribution records for the package in any
    revision; a CVE outside it is unknown to the tracker rather than fixed.
    """

    def __init__(self) -> None:
        super().__init__()
        self.tracked: Dict[PackageKey, Set[str]] = {}


class _Budget:
    """Upper bound on outbound requests for one lookup."""

    def __init__(self, limit: int) -> None:
        self.remaining = max(0, int(limit))

    def take(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


def _default_http_post(url: str, payload: Dict[str, Any], timeout: float) -> Any:
    import httpx

    resp = httpx.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _default_http_get(url: str, timeout: float) -> Any:
    import httpx

    resp = httpx.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _ecosystem(purl_type: str, namespace: str, distro: str) -> Optional[str]:
    """OSV ecosystem string for a distribution release, or None when unsupported."""
    distro = distro.strip().lower()
    if purl_type == "deb" and namespace == "debian":
        m = re.fullmatch(r"debian-(\d+)(?:\.\d+)*", distro)
        return f"Debian:{m.group(1)}" if m else None
    if purl_type == "apk" and namespace == "alpine":
        m = re.fullmatch(r"alpine-(\d+)\.(\d+)(?:\.\d+)*", distro)
        return f"Alpine:v{m.group(1)}.{m.group(2)}" if m else None
    return None


def _comparable(ecosystem: str, version: str) -> bool:
    """Whether OSV can order ``version`` against the fix versions of ``ecosystem``.

    An unsupported ecosystem string is not comparable either: the verdict logic
    was only verified against the Debian and Alpine trackers.
    """
    m = _ECOSYSTEM_RE.fullmatch(ecosystem)
    if not m:
        return False
    pattern = _DEBIAN_VERSION_RE if m.group(1) else _ALPINE_VERSION_RE
    return pattern.fullmatch(version) is not None


def distro_package(purl: Optional[str]) -> Optional[PackageKey]:
    """Return (OSV ecosystem, source package, version) for a Debian or Alpine PURL.

    The distribution trackers are keyed by source package, so the ``upstream``
    qualifier (``libssl3`` is built from ``openssl``) replaces the binary name
    when present. The release comes from the ``distro`` qualifier; without a
    recognisable release the advisory stream is unknown and None is returned,
    as it is for every other package type. A version outside the ecosystem
    grammar also yields None, because OSV would treat it as fully patched.
    """
    if not purl or not isinstance(purl, str):
        return None
    body = purl.strip().split("#", 1)[0]
    if not body.lower().startswith("pkg:"):
        return None
    body, _, query = body[4:].partition("?")
    path, _, version = body.partition("@")
    segments = [unquote(s) for s in path.split("/") if s]
    if len(segments) != 3:
        return None
    purl_type, namespace, name = (s.strip().lower() for s in segments)
    version = unquote(version).strip()

    qualifiers = {k.lower(): v for k, v in parse_qsl(query, keep_blank_values=False)}
    ecosystem = _ecosystem(purl_type, namespace, qualifiers.get("distro", ""))
    if ecosystem is None:
        return None

    # Syft writes ``upstream=<source>`` and appends ``@<source version>`` when
    # the source revision differs from the binary one.
    source, _, source_version = qualifiers.get("upstream", "").strip().partition("@")
    name = source.strip().lower() or name
    version = source_version.strip() or version
    if not name or not version:
        return None
    if not _comparable(ecosystem, version):
        logger.warning("osv_version_not_comparable", ecosystem=ecosystem, package=name)
        return None
    return ecosystem, name, version


def _cve_ids(values: Any) -> Set[str]:
    """CVE identifiers found in a list of advisory ids (non-lists yield nothing)."""
    out: Set[str] = set()
    if isinstance(values, list):
        for v in values:
            if isinstance(v, str):
                out.update(m.upper() for m in _CVE_RE.findall(v))
    return out


def _query_batch(
    queries: List[Dict[str, Any]],
    *,
    http_post: HttpPost,
    timeout: float,
    budget: _Budget,
    api_url: str,
) -> List[Optional[List[str]]]:
    """Advisory ids per query, following pagination; None marks an incomplete answer."""
    ids: List[List[str]] = [[] for _ in queries]
    complete = [False] * len(queries)
    pending: List[Tuple[int, Optional[str]]] = [(i, None) for i in range(len(queries))]

    while pending:
        if not budget.take():
            logger.warning("osv_request_budget_exhausted", unresolved=len(pending))
            break
        payload = {
            "queries": [
                {**queries[i], **({"page_token": token} if token else {})}
                for i, token in pending
            ]
        }
        try:
            data = http_post(f"{api_url}/v1/querybatch", payload, timeout)
            results = data["results"]
            if not isinstance(results, list) or len(results) != len(pending):
                raise ValueError("querybatch result count does not match the request")
            parsed: List[Tuple[List[str], Optional[str]]] = []
            for res in results:
                if not isinstance(res, dict):
                    raise ValueError("querybatch result is not an object")
                vulns = res.get("vulns") or []
                if not isinstance(vulns, list):
                    raise ValueError("querybatch vulns is not a list")
                page_ids = []
                for v in vulns:
                    if not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"]:
                        raise ValueError("querybatch advisory has no id")
                    page_ids.append(v["id"])
                token = res.get("next_page_token")
                if token is not None and not isinstance(token, str):
                    raise ValueError("querybatch page token is not a string")
                parsed.append((page_ids, token or None))
        except Exception as exc:  # fail-safe: an unusable answer is no answer
            logger.warning("osv_querybatch_failed", error=str(exc), queries=len(pending))
            break

        nxt: List[Tuple[int, Optional[str]]] = []
        for (i, _), (page_ids, token) in zip(pending, parsed):
            ids[i].extend(page_ids)
            if token:
                nxt.append((i, token))
            else:
                complete[i] = True
        pending = nxt

    return [ids[i] if complete[i] else None for i in range(len(queries))]


def _resolve(
    advisory_id: str,
    *,
    http_get: HttpGet,
    timeout: float,
    budget: _Budget,
    api_url: str,
    cache: Dict[str, Optional[Set[str]]],
) -> Optional[Set[str]]:
    """CVE ids an advisory stands for, or None when that cannot be established."""
    direct = _DIRECT_ID_RE.match(advisory_id)
    if direct:
        return {direct.group(1).upper()}
    if advisory_id in cache:
        return cache[advisory_id]
    resolved: Optional[Set[str]] = None
    if budget.take():
        try:
            record = http_get(f"{api_url}/v1/vulns/{quote(advisory_id, safe='')}", timeout)
            if not isinstance(record, dict) or record.get("id") != advisory_id:
                raise ValueError("advisory record does not match the requested id")
            resolved = set()
            for field in _ALIAS_FIELDS:
                resolved |= _cve_ids(record.get(field))
        except Exception as exc:
            logger.warning("osv_advisory_lookup_failed", advisory=advisory_id, error=str(exc))
            resolved = None
    else:
        logger.warning("osv_request_budget_exhausted", advisory=advisory_id)
    cache[advisory_id] = resolved
    return resolved


def osv_vulnerable_cves(
    packages: Iterable[PackageKey],
    *,
    http_post: HttpPost = _default_http_post,
    http_get: HttpGet = _default_http_get,
    timeout: float = DEFAULT_TIMEOUT,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    api_url: str = OSV_API_URL,
) -> OsvResult:
    """Ask OSV which CVEs still affect each (ecosystem, package, version).

    ``POST /v1/querybatch`` returns advisory ids only. Tracker ids embed their
    CVE; any other id (a DSA, for example) is resolved with
    ``GET /v1/vulns/{id}`` through its ``aliases``, ``upstream`` and ``related``
    fields. A package is included in the result only when its affected set was
    read completely, every advisory in it was resolved, and a version-less
    query shows that OSV tracks the package at all. A key whose version does
    not follow the Debian or Alpine version grammar is dropped before any
    request, since OSV would answer it as if it were fully patched. Any error, timeout,
    malformed response or exhausted request budget leaves the package out,
    which downstream reads as ``no_distro_data``.
    """
    result = OsvResult()
    keys: List[PackageKey] = []
    skipped = 0
    for key in dict.fromkeys(packages):
        # Keys built by hand bypass distro_package, so the version grammar is
        # enforced again here; an unparsable version must never reach OSV.
        if (
            isinstance(key, tuple) and len(key) == 3
            and all(isinstance(p, str) and p for p in key)
            and _comparable(key[0], key[2])
        ):
            keys.append(key)
        else:
            skipped += 1
    if skipped:
        logger.warning("osv_package_keys_skipped", skipped=skipped)
    if not keys:
        return result

    budget = _Budget(max_requests)
    cache: Dict[str, Optional[Set[str]]] = {}
    try:
        for start in range(0, len(keys), _BATCH_SIZE):
            chunk = keys[start:start + _BATCH_SIZE]
            common = dict(http_post=http_post, timeout=timeout, budget=budget, api_url=api_url)
            affected = _query_batch(
                [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk],
                **common,
            )
            # The tracked set is shared by every revision of a source package.
            sources = list(dict.fromkeys((e, n) for e, n, _ in chunk))
            tracked_ids = dict(zip(sources, _query_batch(
                [{"package": {"name": n, "ecosystem": e}} for e, n in sources], **common,
            )))

            for key, advisory_ids in zip(chunk, affected):
                all_ids = tracked_ids.get(key[:2])
                # An incomplete tracked list only shrinks what may be called
                # fixed, so it is kept; an empty one means OSV has no data.
                tracked = {
                    m.group(1).upper()
                    for m in map(_DIRECT_ID_RE.match, all_ids or []) if m
                }
                if advisory_ids is None or not tracked:
                    continue
                cves: Set[str] = set()
                for advisory_id in advisory_ids:
                    resolved = _resolve(
                        advisory_id, http_get=http_get, timeout=timeout,
                        budget=budget, api_url=api_url, cache=cache,
                    )
                    if resolved is None:
                        break
                    cves |= resolved
                else:
                    result[key] = cves
                    result.tracked[key] = tracked | cves
    except Exception as exc:  # never let the optional check break triage
        logger.warning("osv_lookup_failed", error=str(exc))

    logger.info(
        "osv_lookup_done", requested=len(keys), answered=len(result),
        requests_left=budget.remaining,
    )
    return result


def backport_verdict(
    cve_id: str,
    package_key: Optional[PackageKey],
    osv_result: Optional[Dict[PackageKey, Set[str]]],
) -> str:
    """Distribution verdict for one CVE on one installed package.

    ``fixed_by_distro`` requires positive evidence on both sides: OSV answered
    for exactly this ecosystem, package and version, and the distribution
    tracks the CVE for the package. A missing answer, or a CVE the tracker has
    not recorded, is ``no_distro_data`` and must not suppress a finding.
    """
    try:
        if not cve_id or package_key is None or not osv_result:
            return NO_DISTRO_DATA
        affected = osv_result.get(package_key)
        if affected is None:
            return NO_DISTRO_DATA
        cve = str(cve_id).strip().upper()
        if cve in {str(c).upper() for c in affected}:
            return CONFIRMED_BY_DISTRO
        tracked = (getattr(osv_result, "tracked", None) or {}).get(package_key) or set()
        if cve in {str(c).upper() for c in tracked}:
            return FIXED_BY_DISTRO
    except Exception as exc:
        logger.warning("osv_verdict_failed", cve_id=str(cve_id), error=str(exc))
    return NO_DISTRO_DATA


def backport_verdicts(
    cve_id: str,
    purls: Sequence[Optional[str]],
    osv_result: Optional[Dict[PackageKey, Set[str]]],
) -> Dict[str, str]:
    """Verdict per PURL for one CVE; PURLs outside Debian and Alpine get no_distro_data."""
    return {
        p: backport_verdict(cve_id, distro_package(p), osv_result)
        for p in purls if p
    }
