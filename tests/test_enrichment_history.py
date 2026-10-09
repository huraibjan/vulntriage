"""Unit tests for append-only, idempotent EPSS and KEV ingestion.

Everything here is offline: feeds are literal fixtures, HTTP is patched, and
persistence goes through an in-memory SignalStore, so the idempotency rules
are verified without a database.
"""

from __future__ import annotations

import gzip
import json
from datetime import date, datetime, time, timedelta
from typing import Any, Dict, List, Optional, Set

import pytest

from app.ingest import enrichment_providers as ep
from app.ingest.enrichment_providers import (
    EPSSProvider,
    KEVProvider,
    ingest_epss_feed,
    ingest_kev_catalog,
    parse_epss_csv,
    parse_epss_header,
    parse_kev_catalog,
)

EPSS_DAY1 = (
    "#model_version:v2026.06.15,score_date:2026-10-08T12:00:21Z\n"
    "cve,epss,percentile\n"
    "CVE-2024-0001,0.03351,0.88354\n"
    "CVE-2024-0002,0.27858,0.98053\n"
    "CVE-2099-9999,0.5,0.99\n"  # not present in the vulnerability table
)
EPSS_DAY2 = (
    "#model_version:v2026.06.15,score_date:2026-10-09T12:00:19Z\n"
    "cve,epss,percentile\n"
    "CVE-2024-0001,0.04000,0.90000\n"
    "CVE-2024-0002,0.27858,0.98053\n"
)


def _kev_doc(**status: str) -> Dict[str, Any]:
    """A two-entry catalog; keyword arguments override ransomware status by key."""
    return {
        "catalogVersion": "2026.10.08",
        "dateReleased": "2026-10-08T20:09:18.9833Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "dateAdded": "2024-07-01",
                "shortDescription": "First entry.",
                "knownRansomwareCampaignUse": status.get("first", "Unknown"),
            },
            {
                "cveID": "CVE-2024-0002",
                "dateAdded": "2025-01-15",
                "shortDescription": "Second entry.",
                "knownRansomwareCampaignUse": status.get("second", "Known"),
            },
        ],
    }


class FakeStore:
    """In-memory SignalStore that can only append, mirroring the SQL store."""

    def __init__(self, cves: List[str]) -> None:
        self.vulns = {cve: f"id-{cve}" for cve in cves}
        self.rows: List[Dict[str, Any]] = []
        self.commits = 0
        self.locks = 0

    def acquire_lock(self) -> None:
        self.locks += 1

    def vulnerability_ids_by_cve(self) -> Dict[str, Any]:
        return dict(self.vulns)

    def observed_vulnerability_ids(
        self, signal_type: str, *, day: Optional[date] = None, source: Optional[str] = None
    ) -> Set[Any]:
        out = set()
        for row in self.rows:
            if row["signal_type"] != signal_type:
                continue
            if source is not None and row.get("source") != source:
                continue
            if day is not None:
                start = datetime.combine(day, time.min)
                if not start <= row["observed_at"] < start + timedelta(days=1):
                    continue
            out.add(row["vulnerability_id"])
        return out

    def latest_text_by_vulnerability(self, signal_type: str, *, source: str) -> Dict[Any, Optional[str]]:
        matching = [
            (row["observed_at"], index, row)
            for index, row in enumerate(self.rows)
            if row["signal_type"] == signal_type and row.get("source") == source
        ]
        return {row["vulnerability_id"]: row.get("value_text") for _, _, row in sorted(matching, key=lambda m: m[:2])}

    def add_observations(self, rows: List[Dict[str, Any]]) -> int:
        self.rows.extend(dict(row) for row in rows)
        return len(rows)

    def commit(self) -> None:
        self.commits += 1

    def of_type(self, signal_type: str) -> List[Dict[str, Any]]:
        return [row for row in self.rows if row["signal_type"] == signal_type]


@pytest.fixture
def store() -> FakeStore:
    return FakeStore(["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"])


# ── EPSS parsing ──────────────────────────────────────────────────────────

class TestEPSSParsing:
    def test_header_carries_model_version_and_score_date(self):
        meta = parse_epss_header("#model_version:v2026.06.15,score_date:2026-10-08T12:00:21Z")
        # The timestamp itself contains colons; only the first one separates key from value.
        assert meta == {"model_version": "v2026.06.15", "score_date": "2026-10-08T12:00:21Z"}

    def test_non_comment_line_is_not_a_header(self):
        assert parse_epss_header("cve,epss,percentile") == {}

    def test_csv_is_parsed_with_header_metadata(self):
        feed = parse_epss_csv(EPSS_DAY1)
        assert feed.score_date == date(2026, 10, 8)
        assert feed.model_version == "v2026.06.15"
        assert feed.score_timestamp == "2026-10-08T12:00:21Z"
        assert [s.cve_id for s in feed.scores] == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2099-9999"]
        assert feed.scores[0].epss == pytest.approx(0.03351)
        assert feed.scores[0].percentile == "0.88354"
        assert feed.malformed_rows == 0

    def test_malformed_rows_are_counted_not_ingested(self):
        text = (
            "#model_version:v1,score_date:2026-10-08T00:00:00Z\n"
            "cve,epss,percentile\n"
            "CVE-2024-0001,not-a-number,0.5\n"
            "CVE-2024-0002,1.7,0.5\n"
            "garbage,0.1,0.5\n"
            "cve-2024-0003,0.2,0.5\n"
        )
        feed = parse_epss_csv(text)
        assert feed.malformed_rows == 3
        assert [s.cve_id for s in feed.scores] == ["CVE-2024-0003"]

    def test_headerless_file_requires_an_explicit_date(self):
        text = "cve,epss,percentile\nCVE-2024-0001,0.1,0.5\n"
        with pytest.raises(ValueError):
            parse_epss_csv(text)
        feed = parse_epss_csv(text, fallback_date=date(2021, 5, 1))
        assert feed.score_date == date(2021, 5, 1)
        assert feed.model_version is None

    def test_unexpected_columns_are_rejected(self):
        with pytest.raises(ValueError):
            parse_epss_csv("#model_version:v1,score_date:2026-10-08T00:00:00Z\nfoo,bar\n1,2\n")


class TestEPSSFetchDaily:
    def test_gzip_download_is_decoded(self, monkeypatch):
        requested: List[str] = []

        def fake_read(source: str, *, timeout: float) -> bytes:
            requested.append(source)
            return gzip.compress(EPSS_DAY1.encode("utf-8"))

        monkeypatch.setattr(ep, "_read_source", fake_read)
        feed = EPSSProvider().fetch_daily()
        assert requested == [EPSSProvider.BULK_URL.format(tag="current")]
        assert feed.score_date == date(2026, 10, 8)
        assert len(feed.scores) == 3

    def test_dated_request_uses_dated_file_and_checks_the_date(self, monkeypatch):
        requested: List[str] = []

        def fake_read(source: str, *, timeout: float) -> bytes:
            requested.append(source)
            return EPSS_DAY1.encode("utf-8")

        monkeypatch.setattr(ep, "_read_source", fake_read)
        EPSSProvider().fetch_daily(score_date=date(2026, 10, 8))
        assert requested == [EPSSProvider.BULK_URL.format(tag="2026-10-08")]
        # A file whose header disagrees with the requested date must not be
        # stored under the requested date.
        with pytest.raises(ValueError):
            EPSSProvider().fetch_daily(score_date=date(2026, 10, 7))

    def test_local_gzip_path_is_read(self, tmp_path):
        path = tmp_path / "epss_scores-2026-10-09.csv.gz"
        path.write_bytes(gzip.compress(EPSS_DAY2.encode("utf-8")))
        feed = EPSSProvider().fetch_daily(source=str(path))
        assert feed.score_date == date(2026, 10, 9)

    def test_http_failure_propagates(self, monkeypatch):
        def failing_get(*args: Any, **kwargs: Any):
            raise ep.httpx.ConnectError("network unreachable")

        monkeypatch.setattr(ep.httpx, "get", failing_get)
        with pytest.raises(ep.httpx.ConnectError):
            EPSSProvider().fetch_daily()


# ── EPSS idempotency ──────────────────────────────────────────────────────

class TestEPSSIngestion:
    def test_first_run_inserts_known_cves_only(self, store):
        counts = ingest_epss_feed(parse_epss_csv(EPSS_DAY1), store)
        assert (counts.inserted, counts.skipped_existing, counts.skipped_unknown_cve) == (2, 0, 1)
        assert counts.skipped == 1
        assert store.commits == 1 and store.locks == 1
        row = store.rows[0]
        assert row["signal_type"] == "epss" and row["source"] == "first.org"
        assert row["observed_at"] == datetime(2026, 10, 8)
        assert row["value_num"] == pytest.approx(0.03351)
        assert row["value_text"] == "0.88354"

    def test_model_version_is_recorded_in_evidence_ref(self, store):
        ingest_epss_feed(parse_epss_csv(EPSS_DAY1), store)
        evidence = json.loads(store.rows[0]["evidence_ref"])
        assert evidence == {"model_version": "v2026.06.15", "score_date": "2026-10-08T12:00:21Z"}

    def test_rerun_of_same_score_date_inserts_nothing(self, store):
        ingest_epss_feed(parse_epss_csv(EPSS_DAY1), store)
        before = [dict(r) for r in store.rows]
        counts = ingest_epss_feed(parse_epss_csv(EPSS_DAY1), store)
        assert (counts.inserted, counts.skipped_existing) == (0, 2)
        assert store.rows == before

    def test_new_score_date_appends_and_preserves_history(self, store):
        ingest_epss_feed(parse_epss_csv(EPSS_DAY1), store)
        day1 = [dict(r) for r in store.rows]
        counts = ingest_epss_feed(parse_epss_csv(EPSS_DAY2), store)
        assert counts.inserted == 2
        assert store.rows[:2] == day1  # earlier observations are untouched
        history = sorted(
            (r["observed_at"], r["value_num"])
            for r in store.rows
            if r["vulnerability_id"] == "id-CVE-2024-0001"
        )
        assert history == [(datetime(2026, 10, 8), 0.03351), (datetime(2026, 10, 9), 0.04)]

    def test_existing_row_from_another_source_on_the_same_day_blocks_insert(self, store):
        # Rows written by the earlier ingest path carry a time of 00:00 and no
        # provenance; they still occupy the (CVE, score date) slot.
        store.rows.append({
            "vulnerability_id": "id-CVE-2024-0001", "signal_type": "epss",
            "observed_at": datetime(2026, 10, 8, 6, 30), "value_num": 0.9,
            "source": "legacy", "value_text": None,
        })
        counts = ingest_epss_feed(parse_epss_csv(EPSS_DAY1), store)
        assert (counts.inserted, counts.skipped_existing) == (1, 1)
        assert store.rows[0]["value_num"] == 0.9  # not overwritten

    def test_cve_repeated_within_one_file_is_inserted_once(self, store):
        text = EPSS_DAY1 + "CVE-2024-0001,0.5,0.9\n"
        counts = ingest_epss_feed(parse_epss_csv(text), store)
        assert (counts.inserted, counts.skipped_existing) == (2, 1)

    def test_partial_earlier_run_is_completed(self, store):
        ingest_epss_feed(parse_epss_csv(EPSS_DAY1.replace("CVE-2024-0002,0.27858,0.98053\n", "")), store)
        counts = ingest_epss_feed(parse_epss_csv(EPSS_DAY1), store)
        assert (counts.inserted, counts.skipped_existing) == (1, 1)


# ── KEV parsing ───────────────────────────────────────────────────────────

class TestKEVParsing:
    def test_catalog_fields_are_captured(self):
        catalog = parse_kev_catalog(_kev_doc())
        assert catalog.catalog_version == "2026.10.08"
        # CISA emits four fractional digits; the timestamp must still parse.
        assert catalog.released_at == datetime(2026, 10, 8, 20, 9, 18, 983300)
        first, second = catalog.entries
        assert (first.cve_id, first.date_added, first.ransomware_use) == (
            "CVE-2024-0001", date(2024, 7, 1), "Unknown",
        )
        assert (second.date_added, second.ransomware_use) == (date(2025, 1, 15), "Known")
        assert second.short_description == "Second entry."

    def test_missing_fields_do_not_raise(self):
        catalog = parse_kev_catalog({"vulnerabilities": [
            {"cveID": "CVE-2024-0003"},
            {"cveID": ""},
            {"vendorProject": "no id"},
        ]})
        assert catalog.malformed_entries == 2
        entry = catalog.entries[0]
        assert entry.date_added is None and entry.ransomware_use is None
        assert catalog.released_at is None

    def test_provider_fetch_keeps_legacy_shape_and_adds_fields(self, monkeypatch):
        monkeypatch.setattr(
            ep, "_read_source", lambda source, *, timeout: json.dumps(_kev_doc()).encode("utf-8")
        )
        records = KEVProvider().fetch()
        assert records[1]["cve_id"] == "CVE-2024-0002"
        assert records[1]["observed_at"] == "2025-01-15"
        assert records[1]["value_bool"] is True
        assert records[1]["date_added"] == "2025-01-15"
        assert records[1]["known_ransomware_campaign_use"] == "Known"

    def test_provider_fetch_returns_empty_on_http_failure(self, monkeypatch):
        def failing_get(*args: Any, **kwargs: Any):
            raise ep.httpx.ConnectError("network unreachable")

        monkeypatch.setattr(ep.httpx, "get", failing_get)
        assert KEVProvider().fetch() == []
        with pytest.raises(ep.httpx.ConnectError):
            KEVProvider().fetch_catalog()


# ── KEV idempotency ───────────────────────────────────────────────────────

class TestKEVIngestion:
    def test_first_run_writes_listing_and_ransomware_status(self, store):
        counts = ingest_kev_catalog(parse_kev_catalog(_kev_doc()), store)
        assert counts.inserted == 4
        assert counts.detail["kev_inserted"] == 2
        assert counts.detail["ransomware_inserted"] == 2

        listing = store.of_type("kev")[1]
        assert listing["observed_at"] == datetime(2025, 1, 15)  # CISA dateAdded
        assert listing["value_bool"] is True
        assert listing["value_text"] == "Second entry."
        assert listing["source"] == "cisa_kev"

        status = store.of_type("kev_ransomware")
        assert [(s["value_text"], s["value_bool"]) for s in status] == [("Unknown", False), ("Known", True)]
        # The status is dated when it was observed, not at dateAdded.
        assert status[1]["observed_at"] == datetime(2026, 10, 8, 20, 9, 18, 983300)
        assert json.loads(status[1]["evidence_ref"]) == {
            "catalog_version": "2026.10.08", "date_added": "2025-01-15",
        }

    def test_rerun_of_unchanged_catalog_inserts_nothing(self, store):
        ingest_kev_catalog(parse_kev_catalog(_kev_doc()), store)
        before = [dict(r) for r in store.rows]
        counts = ingest_kev_catalog(parse_kev_catalog(_kev_doc()), store)
        assert counts.inserted == 0
        assert counts.skipped_existing == 4
        assert store.rows == before

    def test_ransomware_status_change_appends_one_row(self, store):
        ingest_kev_catalog(parse_kev_catalog(_kev_doc()), store)
        later = parse_kev_catalog(_kev_doc(first="Known"))
        counts = ingest_kev_catalog(later, store, observed_at=datetime(2026, 11, 1))
        assert counts.inserted == 1
        assert counts.detail["kev_inserted"] == 0
        history = [
            (r["observed_at"], r["value_text"])
            for r in store.of_type("kev_ransomware")
            if r["vulnerability_id"] == "id-CVE-2024-0001"
        ]
        assert history == [
            (datetime(2026, 10, 8, 20, 9, 18, 983300), "Unknown"),
            (datetime(2026, 11, 1), "Known"),
        ]
        # The changed status is now the latest, so a further run is a no-op.
        assert ingest_kev_catalog(later, store, observed_at=datetime(2026, 11, 2)).inserted == 0

    def test_existing_listing_gains_status_without_a_duplicate_listing(self, store):
        # State of the current database: a cisa_kev listing with no status row.
        store.rows.append({
            "vulnerability_id": "id-CVE-2024-0001", "signal_type": "kev",
            "observed_at": datetime(2024, 7, 1), "value_bool": True, "source": "cisa_kev",
        })
        counts = ingest_kev_catalog(parse_kev_catalog(_kev_doc()), store)
        assert counts.detail["kev_inserted"] == 1
        assert counts.detail["kev_skipped_existing"] == 1
        assert counts.detail["ransomware_inserted"] == 2
        assert len([r for r in store.of_type("kev") if r["vulnerability_id"] == "id-CVE-2024-0001"]) == 1

    def test_listing_from_another_source_does_not_block_the_cisa_listing(self, store):
        store.rows.append({
            "vulnerability_id": "id-CVE-2024-0001", "signal_type": "kev",
            "observed_at": datetime(2026, 3, 2, 6, 53), "value_bool": True, "source": "vulndb_ingest",
        })
        counts = ingest_kev_catalog(parse_kev_catalog(_kev_doc()), store)
        assert counts.detail["kev_inserted"] == 2

    def test_unknown_cve_and_undated_listing_are_skipped(self, store):
        doc = _kev_doc()
        doc["vulnerabilities"].append({"cveID": "CVE-2099-0001", "dateAdded": "2026-01-01"})
        doc["vulnerabilities"].append({"cveID": "CVE-2024-0003"})  # no dateAdded, no status
        counts = ingest_kev_catalog(parse_kev_catalog(doc), store)
        assert counts.skipped_unknown_cve == 1
        assert counts.skipped_malformed == 1
        assert not [r for r in store.rows if r["vulnerability_id"] == "id-CVE-2024-0003"]


# ── CLI wiring ────────────────────────────────────────────────────────────

class TestRefreshFeedsCommand:
    def _patch(self, monkeypatch, store: FakeStore, *, kev_fails: bool = False) -> None:
        import contextlib

        import app.db.session as db_session

        @contextlib.contextmanager
        def fake_session():
            yield object()

        def fake_read(source: str, *, timeout: float) -> bytes:
            if "epss" in source:
                return gzip.compress(EPSS_DAY1.encode("utf-8"))
            if kev_fails:
                raise ep.httpx.ConnectError("network unreachable")
            return json.dumps(_kev_doc()).encode("utf-8")

        monkeypatch.setattr(db_session, "get_session", fake_session)
        monkeypatch.setattr(ep, "SqlAlchemySignalStore", lambda session: store)
        monkeypatch.setattr(ep, "_read_source", fake_read)

    def test_runs_both_feeds_and_reports_counts(self, monkeypatch, store):
        from typer.testing import CliRunner

        from app.cli import app as cli_app

        self._patch(monkeypatch, store)
        runner = CliRunner()
        first = runner.invoke(cli_app, ["refresh-feeds"])
        assert first.exit_code == 0, first.output
        assert "epss: inserted=2" in first.output
        assert "kev: inserted=4" in first.output
        assert len(store.rows) == 6

        second = runner.invoke(cli_app, ["refresh-feeds"])
        assert second.exit_code == 0, second.output
        assert "epss: inserted=0" in second.output
        assert "kev: inserted=0" in second.output
        assert len(store.rows) == 6

    def test_one_failing_feed_gives_nonzero_exit_but_keeps_the_other(self, monkeypatch, store):
        from typer.testing import CliRunner

        from app.cli import app as cli_app

        self._patch(monkeypatch, store, kev_fails=True)
        result = CliRunner().invoke(cli_app, ["refresh-feeds"])
        assert result.exit_code == 1
        assert "epss: inserted=2" in result.output
        assert len(store.of_type("epss")) == 2 and not store.of_type("kev")

    def test_malformed_date_is_rejected_before_any_fetch(self, monkeypatch, store):
        from typer.testing import CliRunner

        from app.cli import app as cli_app

        self._patch(monkeypatch, store)
        result = CliRunner().invoke(cli_app, ["refresh-feeds", "--asof", "08-10-2026"])
        assert result.exit_code == 2
        assert store.rows == []
