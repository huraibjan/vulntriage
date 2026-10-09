"""OSV distribution-backport check: PURL mapping, lookup and fail-safe verdicts (offline)."""

import pytest

from app.features.osv_backports import (
    CONFIRMED_BY_DISTRO,
    FIXED_BY_DISTRO,
    NO_DISTRO_DATA,
    OsvResult,
    backport_verdict,
    backport_verdicts,
    distro_package,
    osv_vulnerable_cves,
)

OPENSSL = ("Debian:12", "openssl", "3.0.15-1~deb12u1")
ZLIB = ("Alpine:v3.23", "zlib", "1.3.1-r2")


class FakeOsv:
    """In-memory OSV: ``affected`` by (eco, name, version), ``tracked`` by (eco, name)."""

    def __init__(self, affected=None, tracked=None, records=None, page_size=None):
        self.affected = affected or {}
        self.tracked = tracked or {}
        self.records = records or {}
        self.page_size = page_size
        self.posts = []
        self.gets = []

    def post(self, url, payload, timeout):
        assert url.endswith("/v1/querybatch")
        self.posts.append(payload)
        results = []
        for q in payload["queries"]:
            pkg = q["package"]
            if "version" in q:
                ids = self.affected.get((pkg["ecosystem"], pkg["name"], q["version"]), [])
            else:
                ids = self.tracked.get((pkg["ecosystem"], pkg["name"]), [])
            start = int(q.get("page_token", 0))
            end = len(ids) if self.page_size is None else start + self.page_size
            res = {}
            if ids[start:end]:
                res["vulns"] = [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in ids[start:end]]
            if end < len(ids):
                res["next_page_token"] = str(end)
            results.append(res)
        return {"results": results}

    def get(self, url, timeout):
        advisory_id = url.rsplit("/", 1)[1]
        self.gets.append(advisory_id)
        return self.records[advisory_id]


def _lookup(fake, packages, **kw):
    return osv_vulnerable_cves(packages, http_post=fake.post, http_get=fake.get, **kw)


# --- distro_package ---------------------------------------------------------

def test_debian_binary_package_maps_to_source_and_major_release():
    purl = "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=arm64&distro=debian-12.8&upstream=openssl"
    assert distro_package(purl) == OPENSSL


def test_debian_epoch_and_plus_are_percent_decoded():
    purl = "pkg:deb/debian/zlib1g@1%3A1.2.13.dfsg-1?arch=arm64&distro=debian-12.8&upstream=zlib"
    assert distro_package(purl) == ("Debian:12", "zlib", "1:1.2.13.dfsg-1")
    purl = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u9?arch=arm64&distro=debian-12.8&upstream=glibc"
    assert distro_package(purl) == ("Debian:12", "glibc", "2.36-9+deb12u9")


def test_alpine_release_keeps_major_minor_with_v_prefix():
    assert distro_package("pkg:apk/alpine/zlib@1.3.1-r2?arch=aarch64&distro=alpine-3.23.3") == ZLIB
    purl = "pkg:apk/alpine/libssl3@3.5.5-r0?arch=aarch64&distro=alpine-3.23.3&upstream=openssl"
    assert distro_package(purl) == ("Alpine:v3.23", "openssl", "3.5.5-r0")


def test_upstream_qualifier_with_source_version_overrides_binary_version():
    purl = "pkg:deb/debian/libfoo1@1.2-3%2Bb1?distro=debian-12&upstream=foo%401.2-3"
    assert distro_package(purl) == ("Debian:12", "foo", "1.2-3")


@pytest.mark.parametrize("purl", [
    None,
    "",
    "not-a-purl",
    "pkg:pypi/requests@2.31.0",
    "pkg:golang/github.com/foo/bar@v1.0.0",
    "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-22.04",
    "pkg:deb/debian/openssl@3.0.15-1~deb12u1",                     # release unknown
    "pkg:deb/debian/openssl@3.0.15-1~deb12u1?distro=bookworm",     # no numeric release
    "pkg:deb/debian/openssl?distro=debian-12.8",                   # version unknown
    "pkg:apk/alpine/zlib@1.3.1-r2?distro=alpine-edge",
])
def test_unsupported_or_incomplete_purls_return_none(purl):
    assert distro_package(purl) is None


# --- osv_vulnerable_cves ----------------------------------------------------

def test_tracker_ids_resolve_without_follow_up_requests():
    fake = FakeOsv(
        affected={OPENSSL: ["DEBIAN-CVE-2024-13176"], ZLIB: ["ALPINE-CVE-2026-22184"]},
        tracked={
            OPENSSL[:2]: ["DEBIAN-CVE-2024-13176", "DEBIAN-CVE-2022-0778"],
            ZLIB[:2]: ["ALPINE-CVE-2026-22184"],
        },
    )
    result = _lookup(fake, [OPENSSL, ZLIB])
    assert result == {OPENSSL: {"CVE-2024-13176"}, ZLIB: {"CVE-2026-22184"}}
    assert result.tracked[OPENSSL] == {"CVE-2024-13176", "CVE-2022-0778"}
    assert fake.gets == []
    assert len(fake.posts) == 2  # one versioned batch, one coverage batch


def test_other_advisory_ids_are_resolved_through_the_vulns_endpoint_once():
    other = ("Debian:12", "openssl", "3.0.11-1~deb12u2")
    fake = FakeOsv(
        affected={OPENSSL: ["DSA-6015-1"], other: ["DSA-6015-1", "DEBIAN-CVE-2024-13176"]},
        tracked={OPENSSL[:2]: ["DEBIAN-CVE-2024-13176", "DEBIAN-CVE-2025-9230"]},
        records={"DSA-6015-1": {
            "id": "DSA-6015-1",
            "upstream": ["CVE-2025-9230", "DEBIAN-CVE-2025-9232"],
            "aliases": ["cve-2025-9231"],
        }},
    )
    result = _lookup(fake, [OPENSSL, other])
    assert result[OPENSSL] == {"CVE-2025-9230", "CVE-2025-9232", "CVE-2025-9231"}
    assert result[other] == result[OPENSSL] | {"CVE-2024-13176"}
    assert fake.gets == ["DSA-6015-1"]


def test_pagination_is_followed_for_both_queries():
    affected = [f"DEBIAN-CVE-2025-{1000 + i}" for i in range(5)]
    tracked = affected + [f"DEBIAN-CVE-2020-{1000 + i}" for i in range(4)]
    fake = FakeOsv(affected={OPENSSL: affected}, tracked={OPENSSL[:2]: tracked}, page_size=2)
    result = _lookup(fake, [OPENSSL])
    assert result[OPENSSL] == {i.replace("DEBIAN-", "") for i in affected}
    assert len(result.tracked[OPENSSL]) == 9
    assert any("page_token" in q for p in fake.posts for q in p["queries"])


def test_fully_patched_package_is_present_with_an_empty_affected_set():
    fake = FakeOsv(tracked={OPENSSL[:2]: ["DEBIAN-CVE-2022-0778"]})
    result = _lookup(fake, [OPENSSL])
    assert result == {OPENSSL: set()}
    assert backport_verdict("CVE-2022-0778", OPENSSL, result) == FIXED_BY_DISTRO


def test_package_unknown_to_osv_is_omitted():
    unknown = ("Debian:12", "nonexistent-pkg", "1.0")
    result = _lookup(FakeOsv(), [unknown])
    assert unknown not in result
    assert backport_verdict("CVE-2022-0778", unknown, result) == NO_DISTRO_DATA


def test_duplicate_and_invalid_package_keys_are_ignored():
    fake = FakeOsv(tracked={OPENSSL[:2]: ["DEBIAN-CVE-2022-0778"]})
    result = _lookup(fake, [OPENSSL, OPENSSL, None, ("Debian:12", "", "1"), ("a", "b")])
    assert list(result) == [OPENSSL]
    assert len(fake.posts[0]["queries"]) == 1
    assert _lookup(fake, []) == {}


@pytest.mark.parametrize("error", [TimeoutError("timed out"), ConnectionError("refused")])
def test_network_errors_yield_no_data(error):
    def failing_post(url, payload, timeout):
        raise error

    result = osv_vulnerable_cves([OPENSSL], http_post=failing_post, http_get=lambda u, t: {})
    assert result == {}
    assert backport_verdict("CVE-2022-0778", OPENSSL, result) == NO_DISTRO_DATA


@pytest.mark.parametrize("response", [
    None,
    [],
    {},
    {"results": "oops"},
    {"results": []},                                   # count mismatch
    {"results": [None]},
    {"results": [{"vulns": "oops"}]},
    {"results": [{"vulns": [{"modified": "x"}]}]},     # advisory without id
    {"results": [{"vulns": [], "next_page_token": 7}]},
])
def test_malformed_responses_yield_no_data(response):
    result = osv_vulnerable_cves(
        [OPENSSL], http_post=lambda u, p, t: response, http_get=lambda u, t: {},
    )
    assert result == {}


def test_failed_coverage_query_never_produces_a_fixed_verdict():
    fake = FakeOsv(tracked={OPENSSL[:2]: ["DEBIAN-CVE-2022-0778"]})

    def post(url, payload, timeout):
        if "version" not in payload["queries"][0]:
            raise TimeoutError("timed out")
        return fake.post(url, payload, timeout)

    result = osv_vulnerable_cves([OPENSSL], http_post=post, http_get=fake.get)
    assert result == {}


def test_unresolvable_advisory_drops_the_package():
    fake = FakeOsv(
        affected={OPENSSL: ["DSA-6015-1"]},
        tracked={OPENSSL[:2]: ["DEBIAN-CVE-2025-9230"]},
    )  # no record, so the GET raises KeyError
    result = _lookup(fake, [OPENSSL])
    assert result == {}
    assert backport_verdict("CVE-2025-9230", OPENSSL, result) == NO_DISTRO_DATA


def test_advisory_record_for_another_id_is_rejected():
    fake = FakeOsv(
        affected={OPENSSL: ["DSA-6015-1"]},
        tracked={OPENSSL[:2]: ["DEBIAN-CVE-2025-9230"]},
        records={"DSA-6015-1": {"id": "DSA-1-1", "upstream": ["CVE-2000-0001"]}},
    )
    assert _lookup(fake, [OPENSSL]) == {}


def test_request_budget_bounds_requests_and_fails_safe():
    affected = [f"DEBIAN-CVE-2025-{1000 + i}" for i in range(10)]
    fake = FakeOsv(affected={OPENSSL: affected}, tracked={OPENSSL[:2]: affected}, page_size=1)
    result = _lookup(fake, [OPENSSL], max_requests=3)
    assert len(fake.posts) + len(fake.gets) <= 3
    assert result == {}

    fake = FakeOsv(
        affected={OPENSSL: ["DSA-6015-1"]},
        tracked={OPENSSL[:2]: ["DEBIAN-CVE-2025-9230"]},
        records={"DSA-6015-1": {"id": "DSA-6015-1", "upstream": ["CVE-2025-9230"]}},
    )
    assert _lookup(fake, [OPENSSL], max_requests=2) == {}  # nothing left for the GET
    assert fake.gets == []
    assert _lookup(fake, [OPENSSL], max_requests=0) == {}


def test_timeout_is_passed_to_the_transport():
    seen = []
    fake = FakeOsv(tracked={OPENSSL[:2]: ["DEBIAN-CVE-2022-0778"]})

    def post(url, payload, timeout):
        seen.append(timeout)
        return fake.post(url, payload, timeout)

    osv_vulnerable_cves([OPENSSL], http_post=post, http_get=fake.get, timeout=2.5)
    assert seen == [2.5, 2.5]


# --- backport_verdict -------------------------------------------------------

def _result(affected, tracked):
    r = OsvResult()
    r[OPENSSL] = set(affected)
    r.tracked[OPENSSL] = set(tracked)
    return r


def test_verdicts_for_confirmed_fixed_and_untracked_cves():
    r = _result({"CVE-2024-13176"}, {"CVE-2024-13176", "CVE-2022-0778"})
    assert backport_verdict("cve-2024-13176", OPENSSL, r) == CONFIRMED_BY_DISTRO
    assert backport_verdict("CVE-2022-0778", OPENSSL, r) == FIXED_BY_DISTRO
    # Absent from the affected set but never tracked by the distribution.
    assert backport_verdict("CVE-2099-0001", OPENSSL, r) == NO_DISTRO_DATA


def test_fixed_requires_the_exact_ecosystem_package_and_version():
    r = _result(set(), {"CVE-2022-0778"})
    for key in [
        ("Debian:11", "openssl", OPENSSL[2]),
        ("Debian:12", "libssl3", OPENSSL[2]),
        ("Debian:12", "openssl", "3.0.14-1~deb12u1"),
    ]:
        assert backport_verdict("CVE-2022-0778", key, r) == NO_DISTRO_DATA


@pytest.mark.parametrize("osv_result", [None, {}, OsvResult(), "garbage", 5])
def test_absent_or_unusable_osv_data_is_never_fixed(osv_result):
    assert backport_verdict("CVE-2022-0778", OPENSSL, osv_result) == NO_DISTRO_DATA


def test_plain_mapping_without_tracked_evidence_confirms_but_never_fixes():
    plain = {OPENSSL: {"CVE-2024-13176"}}
    assert backport_verdict("CVE-2024-13176", OPENSSL, plain) == CONFIRMED_BY_DISTRO
    assert backport_verdict("CVE-2022-0778", OPENSSL, plain) == NO_DISTRO_DATA


def test_missing_cve_or_package_key_is_no_data():
    r = _result(set(), {"CVE-2022-0778"})
    assert backport_verdict("", OPENSSL, r) == NO_DISTRO_DATA
    assert backport_verdict("CVE-2022-0778", None, r) == NO_DISTRO_DATA


def test_verdicts_per_purl():
    r = _result(set(), {"CVE-2022-0778"})
    deb = "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=arm64&distro=debian-12.8&upstream=openssl"
    pypi = "pkg:pypi/cryptography@42.0.0"
    assert backport_verdicts("CVE-2022-0778", [deb, pypi, None], r) == {
        deb: FIXED_BY_DISTRO, pypi: NO_DISTRO_DATA,
    }


# OSV answers an unparsable version with the unfixed-only advisories, which
# would read as "fixed" for every other tracked CVE; such versions are refused.
MALFORMED_DEBIAN = ["garbage", "v3.0.15", "3.0.15-", "-1", "1:", "3.0 15", "3.0.15_1", "1:2:3.0", "3.0.15/1"]
MALFORMED_ALPINE = ["garbage", "v1.3.1-r2", "1.3.1", "1.3.1-r", "1.3.1-2", "1.3.1-rc1", "1.3.1_foo-r1", "1..3-r1"]


@pytest.mark.parametrize("version", [
    "3.0.15-1~deb12u1", "1:1.2.13.dfsg-1", "2.36-9+deb12u9", "5.2.15-2+b7", "12", "1.0-2-3",
])
def test_well_formed_debian_versions_are_accepted(version):
    assert distro_package(f"pkg:deb/debian/openssl@{version}?distro=debian-12") == (
        "Debian:12", "openssl", version)


@pytest.mark.parametrize("version", [
    "1.3.1-r2", "1.37.0-r30", "3.5.5-r0", "1.1.1w-r1", "2.0_rc1-r0", "20240101-r0", "1.2_p3_git20240101-r4",
])
def test_well_formed_alpine_versions_are_accepted(version):
    assert distro_package(f"pkg:apk/alpine/zlib@{version}?distro=alpine-3.23.3") == (
        "Alpine:v3.23", "zlib", version)


@pytest.mark.parametrize("version", MALFORMED_DEBIAN)
def test_malformed_debian_version_is_not_mapped(version):
    assert distro_package(f"pkg:deb/debian/openssl@{version}?distro=debian-12") is None


@pytest.mark.parametrize("version", MALFORMED_ALPINE)
def test_malformed_alpine_version_is_not_mapped(version):
    assert distro_package(f"pkg:apk/alpine/zlib@{version}?distro=alpine-3.23.3") is None


def test_malformed_upstream_source_version_is_not_mapped():
    purl = "pkg:deb/debian/libssl3@3.0.15-1?distro=debian-12&upstream=openssl%40garbage"
    assert distro_package(purl) is None


@pytest.mark.parametrize("key", (
    [("Debian:12", "openssl", v) for v in MALFORMED_DEBIAN]
    + [("Alpine:v3.23", "zlib", v) for v in MALFORMED_ALPINE]
    + [("Ubuntu:22.04", "openssl", "3.0.2-0ubuntu1"), ("Debian", "openssl", "3.0.15-1")]
))
def test_malformed_version_is_never_sent_and_never_fixed(key):
    """The fake mimics OSV: an unparsable version still gets the unfixed-only records."""
    source = key[:2]
    fake = FakeOsv(
        affected={key: ["DEBIAN-CVE-2010-0928"]},
        tracked={source: ["DEBIAN-CVE-2010-0928", "DEBIAN-CVE-2022-0778"]},
    )
    result = _lookup(fake, [key])
    assert fake.posts == [] and fake.gets == []
    assert key not in result and key not in result.tracked
    assert backport_verdict("CVE-2022-0778", key, result) == NO_DISTRO_DATA
    assert backport_verdict("CVE-2010-0928", key, result) == NO_DISTRO_DATA


def test_malformed_key_does_not_affect_valid_keys_in_the_same_lookup():
    bad = ("Debian:12", "openssl", "garbage")
    fake = FakeOsv(
        affected={OPENSSL: ["DEBIAN-CVE-2024-13176"], bad: ["DEBIAN-CVE-2010-0928"]},
        tracked={OPENSSL[:2]: ["DEBIAN-CVE-2024-13176", "DEBIAN-CVE-2022-0778"]},
    )
    result = _lookup(fake, [bad, OPENSSL])
    assert set(result) == {OPENSSL}
    sent = [q.get("version") for p in fake.posts for q in p["queries"]]
    assert "garbage" not in sent
    assert backport_verdict("CVE-2022-0778", OPENSSL, result) == FIXED_BY_DISTRO
    assert backport_verdict("CVE-2022-0778", bad, result) == NO_DISTRO_DATA
