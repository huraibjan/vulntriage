"""SBOM / VEX parsing and component identity resolution (no database)."""

from app.ingest.sbom_provider import (
    _parse_csaf_vex,
    _parse_cyclonedx,
    _parse_openvex,
    _parse_spdx,
    _purl_parts,
    detect_sbom_format,
    detect_vex_format,
    resolve_identity,
)

PRODUCTS = {"http_server": {"apache"}, "requests": {"python"}, "http": {"ietf", "golang"}}


def test_cyclonedx_reads_top_level_and_syft_cpes_and_skips_files():
    doc = {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "name": "httpd", "version": "2.4.49",
         "cpe": "cpe:2.3:a:httpd:httpd:2.4.49:*:*:*:*:*:*:*",
         "properties": [{"name": "syft:cpe23",
                         "value": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]},
        {"type": "file", "name": "/usr/local/apache2/bin/httpd"},
    ]}
    parsed = _parse_cyclonedx(doc)
    assert len(parsed) == 1
    comp, candidates = parsed[0]
    assert len(candidates) == 2
    resolved, confidence = resolve_identity(comp, candidates, PRODUCTS)
    assert (resolved.vendor, resolved.product, confidence) == ("apache", "http_server", 1.0)


def test_unverified_cpe_keeps_lower_confidence():
    comp, candidates = _parse_cyclonedx({"components": [
        {"name": "apt", "version": "2.6.1", "cpe": "cpe:2.3:a:apt:apt:2.6.1:*:*:*:*:*:*:*"}]})[0]
    resolved, confidence = resolve_identity(comp, candidates, PRODUCTS)
    assert resolved.product == "apt" and confidence == 0.8


def test_package_name_resolves_only_when_vendor_is_unique():
    comp, cands = _parse_cyclonedx({"components": [
        {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}]})[0]
    resolved, confidence = resolve_identity(comp, cands, PRODUCTS)
    assert (resolved.vendor, confidence) == ("python", 0.6)

    comp, cands = _parse_cyclonedx({"components": [{"name": "http", "version": "1.0"}]})[0]
    _, confidence = resolve_identity(comp, cands, PRODUCTS)
    assert confidence == 0.3  # ambiguous: two vendors publish "http"


def test_spdx_external_refs():
    doc = {"spdxVersion": "SPDX-2.3", "packages": [{
        "name": "openssl", "versionInfo": "3.0.15", "supplier": "Organization: OpenSSL",
        "externalRefs": [
            {"referenceType": "cpe23Type",
             "referenceLocator": "cpe:2.3:a:openssl:openssl:3.0.15:*:*:*:*:*:*:*"},
            {"referenceType": "purl", "referenceLocator": "pkg:generic/openssl@3.0.15"}]}]}
    comp, candidates = _parse_spdx(doc)[0]
    assert comp.vendor == "OpenSSL" and comp.purl.startswith("pkg:generic") and candidates


def test_format_detection():
    assert detect_sbom_format({"bomFormat": "CycloneDX"}) == "cyclonedx"
    assert detect_sbom_format({"spdxVersion": "SPDX-2.3", "packages": []}) == "spdx"
    assert detect_vex_format({"statements": []}) == "openvex"
    assert detect_vex_format({"document": {}, "vulnerabilities": []}) == "csaf_vex"


def test_purl_parts():
    assert _purl_parts("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar") == (
        "org.apache.logging.log4j", "log4j-core")
    assert _purl_parts("not-a-purl") == ("", "")


def test_openvex_products_and_vulnerability_forms():
    doc = {"statements": [
        {"vulnerability": {"name": "CVE-2021-44228"}, "status": "not_affected",
         "justification": "vulnerable_code_not_present",
         "products": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"}]},
        {"vulnerability": "https://nvd.nist.gov/vuln/detail/CVE-2021-45046", "status": "affected",
         "products": ["pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0"]},
        {"vulnerability": {"name": "GHSA-xxxx"}, "status": "affected", "products": ["x"]},
    ]}
    stmts = _parse_openvex(doc)
    assert [s.cve_id for s in stmts] == ["CVE-2021-44228", "CVE-2021-45046"]
    assert stmts[0].product.startswith("pkg:maven")


def test_csaf_product_ids_resolve_to_names():
    doc = {"document": {}, "product_tree": {"branches": [{"branches": [{"product": {
        "product_id": "P1", "name": "Example Server 1.0",
        "product_identification_helper": {"cpe": "cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*"}}}]}]},
        "vulnerabilities": [{"cve": "CVE-2024-0001",
                             "product_status": {"known_not_affected": ["P1"], "first_fixed": ["P1"]}}]}
    stmts = _parse_csaf_vex(doc)
    assert len(stmts) == 1
    assert stmts[0].product.startswith("cpe:2.3:a:example:server")
    assert stmts[0].status.value == "not_affected"
