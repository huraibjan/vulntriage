"""Optional enrichment providers for EPSS, CISA KEV, and MITRE ATT&CK.

These are behind config flags and can be skipped for the happy path.
They add signal_observation rows and vector store entries.

EPSS and KEV ingestion is append-only. An observation is identified by
(CVE, signal type, score date), so a daily job may be re-run without
creating duplicates, and a later score date never replaces an earlier one.
Retaining every dated score is what permits point-in-time evaluation from
the database itself rather than from an external archive.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Set

import httpx

from app.core.logging import get_logger
from app.ingest.base_provider import BaseProvider

log = get_logger(__name__)

EPSS_SIGNAL = "epss"
EPSS_SOURCE = "first.org"
KEV_SIGNAL = "kev"
KEV_RANSOMWARE_SIGNAL = "kev_ransomware"
KEV_SOURCE = "cisa_kev"
KEV_EVIDENCE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# Session-independent key for the Postgres advisory lock that serialises
# concurrent feed refreshes. The table carries no unique constraint on
# (vulnerability, signal, date), so the lock is what prevents two overlapping
# cron runs from both passing the existence check.
_FEED_LOCK_KEY = 7_203_114_506

_INSERT_BATCH = 10_000


# ── Parsed feed structures ────────────────────────────────────────────────

@dataclass(frozen=True)
class EPSSScore:
    """One CVE row of the daily EPSS file."""

    cve_id: str
    epss: float
    percentile: Optional[str]  # kept verbatim, as stored by earlier ingests


@dataclass
class EPSSFeed:
    """A parsed daily EPSS file: header metadata plus one score per CVE."""

    score_date: date
    model_version: Optional[str]
    score_timestamp: Optional[str]  # header value verbatim, e.g. 2026-10-08T12:00:21Z
    scores: List[EPSSScore] = field(default_factory=list)
    malformed_rows: int = 0


@dataclass(frozen=True)
class KEVEntry:
    """One catalog entry of the CISA KEV feed."""

    cve_id: str
    date_added: Optional[date]
    ransomware_use: Optional[str]  # "Known" | "Unknown" | None when absent
    short_description: str = ""


@dataclass
class KEVCatalog:
    """A parsed CISA KEV catalog."""

    catalog_version: Optional[str]
    released_at: Optional[datetime]
    entries: List[KEVEntry] = field(default_factory=list)
    malformed_entries: int = 0


@dataclass
class IngestCounts:
    """Outcome of one idempotent feed ingestion."""

    feed: str
    inserted: int = 0
    skipped_existing: int = 0
    skipped_unknown_cve: int = 0
    skipped_malformed: int = 0
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def skipped(self) -> int:
        return self.skipped_existing + self.skipped_unknown_cve + self.skipped_malformed


# ── Parsing ───────────────────────────────────────────────────────────────

def _parse_date(value: Any) -> Optional[date]:
    """Parse a YYYY-MM-DD prefix; returns None instead of raising."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if not isinstance(value, str) or len(value) < 10:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp to a naive UTC datetime."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    # CISA emits four fractional digits, which fromisoformat rejects.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(ch for ch in tail if ch.isdigit())
        offset = tail[len(digits):]
        text = f"{head}.{(digits + '000000')[:6]}{offset}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        day = _parse_date(value)
        return datetime.combine(day, time.min) if day else None
    if parsed.tzinfo is not None:
        parsed = (parsed - parsed.utcoffset()).replace(tzinfo=None)
    return parsed


def parse_epss_header(line: str) -> Dict[str, str]:
    """Parse the leading comment line of the EPSS file.

    The line has the form ``#model_version:v2026.06.15,score_date:2026-10-08T12:00:21Z``.
    A line that is not a comment yields an empty mapping.
    """
    line = line.strip()
    if not line.startswith("#"):
        return {}
    meta: Dict[str, str] = {}
    for part in line.lstrip("#").split(","):
        key, sep, value = part.partition(":")
        if sep:
            meta[key.strip()] = value.strip()
    return meta


def parse_epss_csv(text: str, *, fallback_date: Optional[date] = None) -> EPSSFeed:
    """Parse the daily EPSS CSV (already decompressed).

    The score date is taken from the header. ``fallback_date`` is used only
    when the header does not carry one (files published before the header was
    introduced); if neither is available the file is rejected, because an
    observation without a trustworthy date would defeat point-in-time use.
    """
    lines = text.splitlines()
    meta: Dict[str, str] = {}
    while lines and lines[0].startswith("#"):
        meta.update(parse_epss_header(lines.pop(0)))

    score_timestamp = meta.get("score_date")
    score_date = _parse_date(score_timestamp) or fallback_date
    if score_date is None:
        raise ValueError("EPSS file carries no score_date header and no date was supplied.")

    feed = EPSSFeed(
        score_date=score_date,
        model_version=meta.get("model_version") or None,
        score_timestamp=score_timestamp,
    )
    reader = csv.DictReader(lines)
    if not reader.fieldnames or "cve" not in reader.fieldnames or "epss" not in reader.fieldnames:
        raise ValueError(f"Unexpected EPSS columns: {reader.fieldnames}")

    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        try:
            epss = float(row.get("epss") or "")
        except ValueError:
            feed.malformed_rows += 1
            continue
        if not cve_id.startswith("CVE-") or not 0.0 <= epss <= 1.0:
            feed.malformed_rows += 1
            continue
        percentile = (row.get("percentile") or "").strip() or None
        feed.scores.append(EPSSScore(cve_id=cve_id, epss=epss, percentile=percentile))
    return feed


def parse_kev_catalog(catalog: Dict[str, Any]) -> KEVCatalog:
    """Parse the CISA KEV JSON document into typed entries."""
    parsed = KEVCatalog(
        catalog_version=catalog.get("catalogVersion") or None,
        released_at=_parse_timestamp(catalog.get("dateReleased")),
    )
    for item in catalog.get("vulnerabilities") or []:
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            parsed.malformed_entries += 1
            continue
        ransomware = item.get("knownRansomwareCampaignUse")
        ransomware = ransomware.strip() if isinstance(ransomware, str) and ransomware.strip() else None
        parsed.entries.append(KEVEntry(
            cve_id=cve_id,
            date_added=_parse_date(item.get("dateAdded")),
            ransomware_use=ransomware,
            short_description=str(item.get("shortDescription") or ""),
        ))
    return parsed


def _read_source(source: str, *, timeout: float) -> bytes:
    """Return the bytes of a local path or an HTTP(S) URL; raises on failure."""
    if source.startswith(("http://", "https://")):
        resp = httpx.get(source, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        return resp.content
    return Path(source).read_bytes()


# ── Persistence boundary ──────────────────────────────────────────────────

class SignalStore(Protocol):
    """The narrow set of storage operations feed ingestion requires.

    Keeping the boundary this small lets the idempotency rules be verified
    against an in-memory implementation, without a database.
    """

    def acquire_lock(self) -> None: ...

    def vulnerability_ids_by_cve(self) -> Dict[str, Any]: ...

    def observed_vulnerability_ids(
        self, signal_type: str, *, day: Optional[date] = None, source: Optional[str] = None
    ) -> Set[Any]: ...

    def latest_text_by_vulnerability(self, signal_type: str, *, source: str) -> Dict[Any, Optional[str]]: ...

    def add_observations(self, rows: List[Dict[str, Any]]) -> int: ...

    def commit(self) -> None: ...


class SqlAlchemySignalStore:
    """SignalStore backed by the signal_observation table. Insert-only."""

    def __init__(self, session: Any) -> None:
        self._session = session

    def acquire_lock(self) -> None:
        """Serialise feed refreshes for the duration of the transaction."""
        from sqlalchemy import text

        bind = self._session.get_bind()
        if bind.dialect.name == "postgresql":
            self._session.execute(
                text("SELECT pg_advisory_xact_lock(:key)"), {"key": _FEED_LOCK_KEY}
            )

    def vulnerability_ids_by_cve(self) -> Dict[str, Any]:
        from app.db.models import Vulnerability

        rows = (
            self._session.query(Vulnerability.cve_id, Vulnerability.id)
            .filter(Vulnerability.cve_id.isnot(None))
            .all()
        )
        return {cve_id.upper(): vuln_id for cve_id, vuln_id in rows}

    def observed_vulnerability_ids(
        self, signal_type: str, *, day: Optional[date] = None, source: Optional[str] = None
    ) -> Set[Any]:
        from app.db.models import SignalObservation

        query = self._session.query(SignalObservation.vulnerability_id).filter(
            SignalObservation.signal_type == signal_type
        )
        if source is not None:
            query = query.filter(SignalObservation.source == source)
        if day is not None:
            start = datetime.combine(day, time.min)
            query = query.filter(
                SignalObservation.observed_at >= start,
                SignalObservation.observed_at < start + timedelta(days=1),
            )
        return {row[0] for row in query.distinct().all()}

    def latest_text_by_vulnerability(self, signal_type: str, *, source: str) -> Dict[Any, Optional[str]]:
        from app.db.models import SignalObservation

        rows = (
            self._session.query(
                SignalObservation.vulnerability_id, SignalObservation.value_text
            )
            .filter(
                SignalObservation.signal_type == signal_type,
                SignalObservation.source == source,
            )
            .order_by(SignalObservation.observed_at.asc(), SignalObservation.id.asc())
            .all()
        )
        # Ascending order, so the last assignment per key is the latest row.
        return {vuln_id: value_text for vuln_id, value_text in rows}

    def add_observations(self, rows: List[Dict[str, Any]]) -> int:
        from app.db.models import SignalObservation

        for start in range(0, len(rows), _INSERT_BATCH):
            self._session.bulk_insert_mappings(
                SignalObservation, rows[start : start + _INSERT_BATCH]
            )
        return len(rows)

    def commit(self) -> None:
        self._session.commit()


# ── Idempotent ingestion ──────────────────────────────────────────────────

def epss_evidence_ref(feed: EPSSFeed) -> str:
    """Provenance stored with every EPSS observation of a feed.

    The EPSS model version is recorded because scores from different model
    versions are not comparable; it is serialised as JSON into the existing
    free-text evidence column, which requires no schema change.
    """
    return json.dumps(
        {"model_version": feed.model_version, "score_date": feed.score_timestamp},
        sort_keys=True,
    )


def ingest_epss_feed(feed: EPSSFeed, store: SignalStore) -> IngestCounts:
    """Append the EPSS scores of one score date.

    A CVE that already holds an EPSS observation on ``feed.score_date`` is
    skipped, whatever its source, so repeating a run inserts nothing. Rows of
    other dates are never read for modification: the function only inserts.
    The whole feed is committed in one transaction.
    """
    counts = IngestCounts(
        feed="epss",
        skipped_malformed=feed.malformed_rows,
        detail={
            "score_date": feed.score_date.isoformat(),
            "model_version": feed.model_version,
        },
    )
    store.acquire_lock()
    vuln_ids = store.vulnerability_ids_by_cve()
    present = set(store.observed_vulnerability_ids(EPSS_SIGNAL, day=feed.score_date))
    observed_at = datetime.combine(feed.score_date, time.min)
    evidence = epss_evidence_ref(feed)

    rows: List[Dict[str, Any]] = []
    for score in feed.scores:
        vuln_id = vuln_ids.get(score.cve_id)
        if vuln_id is None:
            counts.skipped_unknown_cve += 1
            continue
        if vuln_id in present:
            counts.skipped_existing += 1
            continue
        present.add(vuln_id)  # also guards against a CVE repeated within the file
        rows.append({
            "vulnerability_id": vuln_id,
            "signal_type": EPSS_SIGNAL,
            "observed_at": observed_at,
            "value_num": score.epss,
            "value_text": score.percentile,
            "source": EPSS_SOURCE,
            "evidence_ref": evidence,
        })

    counts.inserted = store.add_observations(rows) if rows else 0
    store.commit()
    log.info(
        "epss_feed_ingested",
        score_date=counts.detail["score_date"],
        model_version=feed.model_version,
        inserted=counts.inserted,
        skipped_existing=counts.skipped_existing,
        skipped_unknown_cve=counts.skipped_unknown_cve,
        skipped_malformed=counts.skipped_malformed,
    )
    return counts


def ingest_kev_catalog(
    catalog: KEVCatalog,
    store: SignalStore,
    *,
    observed_at: Optional[datetime] = None,
) -> IngestCounts:
    """Append KEV listings and ransomware-use statuses from one catalog.

    Two kinds of row are written, both insert-only:

    * ``kev`` — one per CVE, dated at CISA's ``dateAdded``. A CVE that already
      holds a ``cisa_kev`` listing is skipped.
    * ``kev_ransomware`` — the ``knownRansomwareCampaignUse`` status, dated at
      the time the status was observed (the catalog release time), because
      the feed does not state when CISA changed it. A row is written only
      when the status differs from the latest recorded one, so the table
      holds the status history and an unchanged catalog inserts nothing.

    The status is kept in a separate signal type so that existing consumers
    of ``kev`` rows, including the label policies, are unaffected.
    """
    counts = IngestCounts(
        feed="kev",
        skipped_malformed=catalog.malformed_entries,
        detail={
            "catalog_version": catalog.catalog_version,
            "kev_inserted": 0,
            "ransomware_inserted": 0,
            "kev_skipped_existing": 0,
            "ransomware_skipped_unchanged": 0,
        },
    )
    status_observed_at = observed_at or catalog.released_at or datetime.utcnow()

    store.acquire_lock()
    vuln_ids = store.vulnerability_ids_by_cve()
    listed = set(store.observed_vulnerability_ids(KEV_SIGNAL, source=KEV_SOURCE))
    latest_status = dict(
        store.latest_text_by_vulnerability(KEV_RANSOMWARE_SIGNAL, source=KEV_SOURCE)
    )

    rows: List[Dict[str, Any]] = []
    for entry in catalog.entries:
        vuln_id = vuln_ids.get(entry.cve_id)
        if vuln_id is None:
            counts.skipped_unknown_cve += 1
            continue

        if vuln_id in listed:
            counts.detail["kev_skipped_existing"] += 1
        elif entry.date_added is None:
            # A listing without its date cannot be placed in time; inserting
            # it under today's date would misstate when exploitation was known.
            counts.skipped_malformed += 1
        else:
            listed.add(vuln_id)
            rows.append({
                "vulnerability_id": vuln_id,
                "signal_type": KEV_SIGNAL,
                "observed_at": datetime.combine(entry.date_added, time.min),
                "value_bool": True,
                "value_text": entry.short_description,
                "source": KEV_SOURCE,
                "evidence_ref": KEV_EVIDENCE_URL,
            })
            counts.detail["kev_inserted"] += 1

        if entry.ransomware_use is None:
            continue
        if vuln_id in latest_status and latest_status[vuln_id] == entry.ransomware_use:
            counts.detail["ransomware_skipped_unchanged"] += 1
            continue
        latest_status[vuln_id] = entry.ransomware_use
        rows.append({
            "vulnerability_id": vuln_id,
            "signal_type": KEV_RANSOMWARE_SIGNAL,
            "observed_at": status_observed_at,
            "value_bool": entry.ransomware_use.lower() == "known",
            "value_text": entry.ransomware_use,
            "source": KEV_SOURCE,
            "evidence_ref": json.dumps(
                {
                    "date_added": entry.date_added.isoformat() if entry.date_added else None,
                    "catalog_version": catalog.catalog_version,
                },
                sort_keys=True,
            ),
        })
        counts.detail["ransomware_inserted"] += 1

    counts.inserted = store.add_observations(rows) if rows else 0
    counts.skipped_existing = (
        counts.detail["kev_skipped_existing"] + counts.detail["ransomware_skipped_unchanged"]
    )
    store.commit()
    log.info(
        "kev_catalog_ingested",
        inserted=counts.inserted,
        skipped_unknown_cve=counts.skipped_unknown_cve,
        skipped_malformed=counts.skipped_malformed,
        **counts.detail,
    )
    return counts


def refresh_epss(
    store: SignalStore,
    *,
    score_date: Optional[date] = None,
    source: Optional[str] = None,
) -> IngestCounts:
    """Fetch one daily EPSS file and append it. Raises if the fetch fails."""
    feed = EPSSProvider().fetch_daily(score_date=score_date, source=source)
    return ingest_epss_feed(feed, store)


def refresh_kev(store: SignalStore, *, source: Optional[str] = None) -> IngestCounts:
    """Fetch the CISA KEV catalog and append it. Raises if the fetch fails."""
    catalog = KEVProvider().fetch_catalog(source=source)
    return ingest_kev_catalog(catalog, store)


# ── EPSS Provider ─────────────────────────────────────────────────────────

class EPSSProvider(BaseProvider):
    """Fetch EPSS scores from the FIRST.org API or local CSV cache."""

    API_URL = "https://api.first.org/data/v1/epss"
    # Daily bulk file covering every scored CVE; one request instead of the
    # several thousand the per-CVE API needs for the full corpus.
    BULK_URL = "https://epss.empiricalsecurity.com/epss_scores-{tag}.csv.gz"

    def name(self) -> str:
        return "epss"

    def fetch_daily(
        self,
        *,
        score_date: Optional[date] = None,
        source: Optional[str] = None,
        timeout: float = 120.0,
    ) -> EPSSFeed:
        """Fetch and parse one daily EPSS file.

        ``source`` may be a URL or a local ``.csv``/``.csv.gz`` path, which
        allows archived files to be backfilled. Without it, the file of
        ``score_date`` is downloaded, or the current file when no date is
        given. Errors propagate so that a scheduled run fails visibly.
        """
        if source is None:
            tag = score_date.isoformat() if score_date else "current"
            source = self.BULK_URL.format(tag=tag)
        raw = _read_source(source, timeout=timeout)
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        feed = parse_epss_csv(raw.decode("utf-8"), fallback_date=score_date)
        if score_date is not None and feed.score_date != score_date:
            raise ValueError(
                f"EPSS file is dated {feed.score_date}, but {score_date} was requested."
            )
        log.info(
            "epss_daily_fetched",
            score_date=feed.score_date.isoformat(),
            model_version=feed.model_version,
            count=len(feed.scores),
            malformed=feed.malformed_rows,
        )
        return feed

    def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Fetch EPSS for a list of CVE IDs or a date.

        kwargs:
            cve_ids: List[str] – specific CVEs to query
            asof: str – date (YYYY-MM-DD), used as the observation timestamp
        """
        cve_ids: List[str] = kwargs.get("cve_ids", [])
        asof = kwargs.get("asof", datetime.utcnow().strftime("%Y-%m-%d"))

        if not cve_ids:
            log.warning("epss_no_cve_ids", msg="No CVE IDs provided; skipping EPSS fetch.")
            return []

        results: List[Dict[str, Any]] = []
        # API supports up to 30 CVEs per request
        batch_size = 30
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i : i + batch_size]
            try:
                resp = httpx.get(
                    self.API_URL,
                    params={"cve": ",".join(batch)},
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json().get("data", [])
                for item in data:
                    results.append({
                        "cve_id": item.get("cve"),
                        "signal_type": "epss",
                        "observed_at": asof,
                        "value_num": float(item.get("epss", 0)),
                        "value_text": str(item.get("percentile", "")),
                        "source": "first.org",
                    })
            except Exception as e:
                log.error("epss_fetch_error", batch=batch, error=str(e))

        log.info("epss_fetched", count=len(results))
        return results


# ── CISA KEV Provider ─────────────────────────────────────────────────────

class KEVProvider(BaseProvider):
    """Fetch CISA Known Exploited Vulnerabilities catalog."""

    CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def name(self) -> str:
        return "kev"

    def fetch_catalog(self, *, source: Optional[str] = None, timeout: float = 60.0) -> KEVCatalog:
        """Fetch and parse the catalog from the CISA URL or a local JSON path.

        Errors propagate so that a scheduled run fails visibly.
        """
        raw = _read_source(source or self.CATALOG_URL, timeout=timeout)
        catalog = parse_kev_catalog(json.loads(raw.decode("utf-8")))
        log.info(
            "kev_catalog_fetched",
            catalog_version=catalog.catalog_version,
            count=len(catalog.entries),
            malformed=catalog.malformed_entries,
        )
        return catalog

    def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Download KEV catalog and return signal dicts."""
        asof = kwargs.get("asof", datetime.utcnow().strftime("%Y-%m-%d"))
        try:
            catalog = self.fetch_catalog()
        except Exception as e:
            log.error("kev_fetch_error", error=str(e))
            return []

        results: List[Dict[str, Any]] = []
        for entry in catalog.entries:
            results.append({
                "cve_id": entry.cve_id,
                "signal_type": KEV_SIGNAL,
                "observed_at": entry.date_added.isoformat() if entry.date_added else asof,
                "value_bool": True,
                "value_text": entry.short_description,
                "source": KEV_SOURCE,
                "evidence_ref": KEV_EVIDENCE_URL,
                "date_added": entry.date_added.isoformat() if entry.date_added else None,
                "known_ransomware_campaign_use": entry.ransomware_use,
            })

        log.info("kev_fetched", count=len(results))
        return results


# ── ATT&CK STIX Provider ─────────────────────────────────────────────────

class ATTCKProvider(BaseProvider):
    """Load MITRE ATT&CK Enterprise techniques from a local STIX 2.1 JSON bundle."""

    def name(self) -> str:
        return "attck"

    def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Parse ATT&CK STIX bundle and return technique dicts.

        kwargs:
            source: str – path to enterprise-attack.json
        """
        source = kwargs.get("source")
        if not source:
            raise ValueError("ATTCKProvider requires --source <path> to STIX JSON.")

        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"ATT&CK file not found: {path}")

        log.info("loading_attck_stix", path=str(path))
        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])
        techniques: List[Dict[str, Any]] = []

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            # Skip revoked / deprecated
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            ext_refs = obj.get("external_references", [])
            technique_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            if not technique_id:
                continue

            # Extract tactic names from kill_chain_phases
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name", ""))

            techniques.append({
                "technique_id": technique_id,
                "technique_name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "stix_id": obj.get("id", ""),
                "object_ref": obj.get("id", ""),
            })

        log.info("attck_techniques_loaded", count=len(techniques))
        return techniques
