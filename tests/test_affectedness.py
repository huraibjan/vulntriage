"""Version-aware affectedness matching and VEX scoping."""

from types import SimpleNamespace
from uuid import uuid4

from app.features.affectedness import (
    MATCH_NONE,
    MATCH_NOT_IN_RANGE,
    MATCH_PRODUCT_ONLY,
    MATCH_VERSION,
    VulnerableRange,
    best_match,
    upstream_version,
    version_key,
    vex_applies,
    vulnerable_ranges,
)


def _vuln(matches, products=None):
    return SimpleNamespace(
        raw_source_json={"configurations": [{"nodes": [{"cpeMatch": matches}]}]} if matches else {},
        affected_products_json=products or [],
    )


def _sw(vendor="apache", product="log4j", version=None, cpe=None, purl=None):
    return SimpleNamespace(vendor=vendor, product=product, version=version, cpe=cpe, purl=purl)


LOG4SHELL = _vuln([
    {"criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "vulnerable": True,
     "versionStartIncluding": "2.13.0", "versionEndExcluding": "2.15.0"},
    {"criteria": "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*", "vulnerable": True},
    {"criteria": "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*", "vulnerable": False},
])


class TestVersionOrdering:
    def test_numeric_parts_compare_numerically(self):
        assert version_key("2.9.0") < version_key("2.14.1")

    def test_letter_suffix(self):
        assert version_key("1.1.1k") < version_key("1.1.1l")

    def test_distribution_revision_is_dropped(self):
        assert upstream_version("3.0.15-1~deb12u1") == "3.0.15"
        assert upstream_version("1:2.36.1-8+deb11u1") == "2.36.1"
        assert upstream_version("1.3.1-r2") == "1.3.1"

    def test_leading_tag_is_dropped(self):
        assert upstream_version("go1.24.6") == "1.24.6"
        assert upstream_version("v1.19.0") == "1.19.0"


class TestRanges:
    def test_bounds(self):
        r = VulnerableRange("apache", "log4j", start_incl="2.13.0", end_excl="2.15.0")
        assert r.contains("2.14.1")
        assert not r.contains("2.15.0")
        assert not r.contains("2.12.4")

    def test_inclusive_end_accepts_packaged_version(self):
        r = VulnerableRange("openssl", "openssl", end_incl="3.0.15")
        assert r.contains("3.0.15-1~deb12u1")

    def test_non_vulnerable_criteria_are_ignored(self):
        assert {r.vendor for r in vulnerable_ranges(LOG4SHELL)} == {"apache"}

    def test_falls_back_to_flattened_products(self):
        v = _vuln(None, [{"vendor": "tukaani", "product": "xz", "version": "5.6.0"},
                         {"vendor": "nghttp2", "product": "nghttp2", "version": "all"}])
        ranges = vulnerable_ranges(v)
        assert ranges[0].exact == "5.6.0"
        assert ranges[1].all_versions


class TestMatching:
    def test_vulnerable_version_is_confirmed(self):
        m = best_match([_sw(version="2.14.1")], LOG4SHELL)
        assert m["level"] == MATCH_VERSION

    def test_patched_version_is_not_in_range(self):
        m = best_match([_sw(version="2.17.1")], LOG4SHELL)
        assert m["level"] == MATCH_NOT_IN_RANGE

    def test_unknown_version_is_product_only(self):
        assert best_match([_sw(version=None)], LOG4SHELL)["level"] == MATCH_PRODUCT_ONLY

    def test_other_product_does_not_match(self):
        assert best_match([_sw(vendor="apache", product="tomcat", version="9.0.1")],
                          LOG4SHELL)["level"] == MATCH_NONE

    def test_identity_comes_from_cpe(self):
        sw = _sw(vendor="unknown", product="httpd", version="2.4.49",
                 cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        v = _vuln([{"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                    "vulnerable": True}])
        assert best_match([sw], v)["level"] == MATCH_VERSION

    def test_strongest_component_wins(self):
        m = best_match([_sw(version="2.17.1"), _sw(version="2.14.0")], LOG4SHELL)
        assert m["level"] == MATCH_VERSION


class TestVexScoping:
    def test_asset_scoped_statement_applies_only_to_that_asset(self):
        asset = uuid4()
        vex = SimpleNamespace(asset_id=asset, vendor="unknown", product="unknown")
        assert vex_applies(vex, asset, [])
        assert not vex_applies(vex, uuid4(), [])

    def test_unscoped_statement_needs_an_installed_product(self):
        vex = SimpleNamespace(asset_id=None, vendor="unknown",
                              product="pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1")
        installed = _sw(purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar")
        assert vex_applies(vex, uuid4(), [installed])
        assert not vex_applies(vex, uuid4(), [_sw(product="tomcat", purl="pkg:maven/x/tomcat@9")])

    def test_statement_for_another_product_never_suppresses(self):
        vex = SimpleNamespace(asset_id=None, vendor="vendor", product="product")
        assert not vex_applies(vex, uuid4(), [_sw(version="2.14.1")])
