"""NVD (National Vulnerability Database) API 2.0 provider.

Fetches vulnerability data from the official NIST NVD REST API.
Supports date-range queries, pagination, rate limiting, and auto-title generation.

API Documentation: https://nvd.nist.gov/developers/vulnerabilities
Rate limits:
  - Without API key: 5 requests per 30-second window
  - With API key: 50 requests per 30-second window
  - Recommended delay: 6 seconds between requests

To get a free API key: https://nvd.nist.gov/developers/request-an-api-key
"""

from __future__ import annotations

import re
import time
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.logging import get_logger
from app.core.settings import get_settings
from app.ingest.base_provider import BaseProvider

log = get_logger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_DATE_RANGE_DAYS = 120  # NVD API constraint
RESULTS_PER_PAGE = 2000    # NVD API max
REQUEST_DELAY_SECONDS = 6  # Recommended by NVD

# CWE short names for title generation
CWE_SHORT_NAMES: Dict[str, str] = {
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Buffer Overflow",
    "CWE-121": "Stack Buffer Overflow",
    "CWE-122": "Heap Buffer Overflow",
    "CWE-125": "Out-of-Bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Disclosure",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Access Control",
    "CWE-287": "Authentication Bypass",
    "CWE-306": "Missing Authentication",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-400": "Resource Exhaustion",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization",
    "CWE-522": "Weak Credentials",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-668": "Exposure of Resource",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-787": "Out-of-Bounds Write",
    "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1321": "Prototype Pollution",
}


class NVDProvider(BaseProvider):
    """Fetches CVE data from the NVD REST API 2.0.
    
    Features:
    - Automatic date-range chunking (≤120 days per request)
    - Pagination support
    - Rate limiting with exponential backoff
    - 3-tier title generation: CISA name → CPE+CWE synthesis → description truncation
    - KEV signal extraction from cisaExploitAdd field
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize NVD provider.
        
        Args:
            api_key: Optional NVD API key for higher rate limits.
                     If not provided, reads from NVD_API env var.
        """
        settings = get_settings()
        self.api_key = api_key or settings.nvd_api
        self._request_count = 0
        self._last_request_time: Optional[float] = None

    def name(self) -> str:
        return "nvd"

    def fetch(
        self,
        start_date: str = "2024-01-01",
        end_date: str = "2024-12-31",
        severity: Optional[str] = None,
        cve_id: Optional[str] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """Fetch CVEs from NVD API.
        
        Args:
            start_date: Start of date range (YYYY-MM-DD). Default: 2024-01-01
            end_date: End of date range (YYYY-MM-DD). Default: 2024-12-31
            severity: Optional severity filter: LOW, MEDIUM, HIGH, CRITICAL
            cve_id: Optional single CVE ID to fetch (bypasses date range)
        
        Returns:
            List of normalized vulnerability records.
        """
        if cve_id:
            # Single CVE lookup
            log.info("nvd_fetch_single", cve_id=cve_id)
            return self._fetch_single_cve(cve_id)

        # Date range fetch with chunking
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")
        
        all_records: List[Dict[str, Any]] = []
        
        # Chunk into ≤120-day windows
        chunks = self._generate_date_chunks(start, end)
        log.info("nvd_fetch_range", start=start_date, end=end_date, n_chunks=len(chunks))
        
        for i, (chunk_start, chunk_end) in enumerate(chunks, 1):
            log.info(
                "nvd_fetch_chunk",
                chunk=i,
                total=len(chunks),
                start=chunk_start.isoformat(),
                end=chunk_end.isoformat(),
            )
            chunk_records = self._fetch_date_range(chunk_start, chunk_end, severity)
            all_records.extend(chunk_records)
            log.info("nvd_chunk_complete", chunk=i, records=len(chunk_records))
        
        log.info("nvd_fetch_complete", total_records=len(all_records))
        return all_records

    def _generate_date_chunks(
        self, start: datetime, end: datetime
    ) -> List[tuple[datetime, datetime]]:
        """Split date range into ≤120-day chunks."""
        chunks = []
        current = start
        while current < end:
            chunk_end = min(current + timedelta(days=MAX_DATE_RANGE_DAYS - 1), end)
            chunks.append((current, chunk_end))
            current = chunk_end + timedelta(days=1)
        return chunks

    def _fetch_date_range(
        self,
        start: datetime,
        end: datetime,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch all CVEs in a single date range (≤120 days) with pagination."""
        records: List[Dict[str, Any]] = []
        start_index = 0
        total_results = None
        
        while True:
            response = self._make_request(
                pub_start_date=start,
                pub_end_date=end,
                severity=severity,
                start_index=start_index,
            )
            
            if total_results is None:
                total_results = response.get("totalResults", 0)
                log.info("nvd_range_total", total=total_results)
            
            vulnerabilities = response.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                normalized = self._normalize_record(vuln)
                if normalized:
                    records.append(normalized)
            
            start_index += len(vulnerabilities)
            if start_index >= total_results:
                break
        
        return records

    def _fetch_single_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Fetch a single CVE by ID."""
        response = self._make_request(cve_id=cve_id)
        vulnerabilities = response.get("vulnerabilities", [])
        
        records = []
        for vuln in vulnerabilities:
            normalized = self._normalize_record(vuln)
            if normalized:
                records.append(normalized)
        return records

    @retry(
        retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TimeoutException)),
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=4, max=60),
    )
    def _make_request(
        self,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        severity: Optional[str] = None,
        cve_id: Optional[str] = None,
        start_index: int = 0,
    ) -> Dict[str, Any]:
        """Make a rate-limited request to the NVD API."""
        # Rate limiting
        self._rate_limit()
        
        # Build params
        params: Dict[str, Any] = {
            "startIndex": start_index,
            "resultsPerPage": RESULTS_PER_PAGE,
        }
        
        if cve_id:
            params["cveId"] = cve_id
        else:
            if pub_start_date:
                params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT00:00:00.000")
            if pub_end_date:
                params["pubEndDate"] = pub_end_date.strftime("%Y-%m-%dT23:59:59.999")
        
        if severity:
            params["cvssV3Severity"] = severity.upper()
        
        # Build headers
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        log.debug("nvd_request", params=params, has_api_key=bool(self.api_key))
        
        with httpx.Client(timeout=60.0) as client:
            response = client.get(NVD_API_BASE, params=params, headers=headers)
            response.raise_for_status()
            self._request_count += 1
            return response.json()

    def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        if self._last_request_time is not None:
            elapsed = time.time() - self._last_request_time
            if elapsed < REQUEST_DELAY_SECONDS:
                sleep_time = REQUEST_DELAY_SECONDS - elapsed
                log.debug("nvd_rate_limit_sleep", seconds=sleep_time)
                time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _normalize_record(self, nvd_vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize NVD API response to canonical schema.
        
        Maps NVD fields to the schema expected by the orchestrator.
        """
        cve = nvd_vuln.get("cve", {})
        if not cve:
            return None
        
        cve_id = cve.get("id")
        if not cve_id:
            return None
        
        # Skip rejected CVEs
        status = cve.get("vulnStatus", "")
        if status.upper() == "REJECTED":
            log.debug("nvd_skip_rejected", cve_id=cve_id)
            return None
        
        # Extract description (English)
        description = self._extract_description(cve)
        
        # Extract CVSS (prefer V3.1 → V3.0 → V4.0 → V2)
        cvss_version, cvss_vector, cvss_score = self._extract_cvss(cve)
        
        # Extract CWE IDs
        cwe_ids = self._extract_cwe_ids(cve)
        
        # Extract references
        references = self._extract_references(cve)
        
        # Extract affected products from configurations
        products = self._extract_products(cve)
        
        # Generate title (3-tier strategy)
        title = self._generate_title(cve, cwe_ids, products)
        
        # Extract CISA KEV signal
        kev_flag = "cisaExploitAdd" in cve and cve["cisaExploitAdd"]
        kev_date = cve.get("cisaExploitAdd")
        
        # Build canonical record
        record: Dict[str, Any] = {
            "source": "nvd",
            "cve_id": cve_id,
            "vuldb_id": None,  # NVD doesn't have VulnDB IDs
            "title": title,
            "description": description,
            "published_at": cve.get("published"),
            "last_modified_at": cve.get("lastModified"),
            "cvss_version": cvss_version,
            "cvss_vector": cvss_vector,
            "cvss_base_score": cvss_score,
            "cwe_ids": cwe_ids,
            "references_json": references,
            "affected_products_json": products,
            "raw_source_json": cve,
            # Signals (NVD provides KEV inline; EPSS must be fetched separately)
            "_signals": {
                "kev_flag": kev_flag,
                "kev_date": kev_date,
                "epss_score": None,  # Must use EPSSProvider separately
                "poc_exploitdb": None,
                "metasploit_module": None,
            },
        }
        
        return record

    def _extract_description(self, cve: Dict[str, Any]) -> str:
        """Extract English description from CVE."""
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        # Fallback to first description
        if descriptions:
            return descriptions[0].get("value", "")
        return ""

    def _extract_cvss(
        self, cve: Dict[str, Any]
    ) -> tuple[Optional[str], Optional[str], Optional[float]]:
        """Extract CVSS metrics with priority: V3.1 → V3.0 → V4.0 → V2.
        
        Prefers 'Primary' type (NVD's own score) over 'Secondary' (submitter's).
        """
        metrics = cve.get("metrics", {})
        
        # Priority order
        metric_keys = [
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV2", "2.0"),
        ]
        
        for key, version in metric_keys:
            metric_list = metrics.get(key, [])
            if not metric_list:
                continue
            
            # Prefer Primary over Secondary
            primary = next((m for m in metric_list if m.get("type") == "Primary"), None)
            metric = primary or metric_list[0]
            
            cvss_data = metric.get("cvssData", {})
            vector = cvss_data.get("vectorString")
            score = cvss_data.get("baseScore")
            
            if vector or score:
                return version, vector, float(score) if score else None
        
        return None, None, None

    def _extract_cwe_ids(self, cve: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs from weaknesses."""
        cwe_ids = []
        weaknesses = cve.get("weaknesses", [])
        
        for weakness in weaknesses:
            descriptions = weakness.get("description", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    value = desc.get("value", "")
                    if value.startswith("CWE-") or value.startswith("NVD-CWE"):
                        cwe_ids.append(value)
        
        return list(set(cwe_ids))  # Deduplicate

    def _extract_references(self, cve: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract references from CVE."""
        refs = []
        for ref in cve.get("references", []):
            refs.append({
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags", []),
            })
        return refs

    def _extract_products(self, cve: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract affected products from CPE configurations."""
        products = []
        seen_cpes = set()
        
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue
                    
                    cpe = cpe_match.get("criteria", "")
                    if cpe in seen_cpes:
                        continue
                    seen_cpes.add(cpe)
                    
                    # Parse CPE: cpe:2.3:a:<vendor>:<product>:<version>:...
                    parsed = self._parse_cpe(cpe)
                    if parsed:
                        products.append(parsed)
        
        return products

    def _parse_cpe(self, cpe: str) -> Optional[Dict[str, str]]:
        """Parse CPE 2.3 URI into vendor/product/version dict."""
        # cpe:2.3:a:vendor:product:version:...
        parts = cpe.split(":")
        if len(parts) < 6:
            return None
        
        return {
            "cpe": cpe,
            "part": parts[2],  # a=application, o=os, h=hardware
            "vendor": parts[3].replace("_", " "),
            "product": parts[4].replace("_", " "),
            "version": parts[5] if parts[5] != "*" else "all",
        }

    def _generate_title(
        self,
        cve: Dict[str, Any],
        cwe_ids: List[str],
        products: List[Dict[str, Any]],
    ) -> Optional[str]:
        """Generate a human-readable title using 3-tier strategy.
        
        1. Use cisaVulnerabilityName if present (best quality)
        2. Synthesize from CPE vendor+product + CWE name
        3. Truncate first sentence of description
        """
        # Tier 1: CISA vulnerability name (only for KEV entries)
        cisa_name = cve.get("cisaVulnerabilityName")
        if cisa_name:
            return cisa_name
        
        # Tier 2: Synthesize from CPE + CWE
        if products and cwe_ids:
            # Get first vendor/product
            vendor = products[0].get("vendor", "").title()
            product = products[0].get("product", "").title()
            
            # Get first CWE short name
            cwe_name = None
            for cwe in cwe_ids:
                if cwe in CWE_SHORT_NAMES:
                    cwe_name = CWE_SHORT_NAMES[cwe]
                    break
            
            if vendor and product:
                if cwe_name:
                    return f"{vendor} {product} {cwe_name} Vulnerability"
                else:
                    return f"{vendor} {product} Vulnerability"
        
        # Tier 2b: CPE only (no CWE)
        if products:
            vendor = products[0].get("vendor", "").title()
            product = products[0].get("product", "").title()
            if vendor and product:
                return f"{vendor} {product} Vulnerability"
        
        # Tier 3: Truncate description
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                text = desc.get("value", "")
                if text:
                    # First sentence, max 120 chars
                    first_sentence = text.split(".")[0]
                    if len(first_sentence) > 120:
                        return first_sentence[:117] + "..."
                    return first_sentence
        
        # Fallback: just the CVE ID
        return cve.get("id")

    def dedupe_key(self, record: Dict[str, Any]) -> str:
        """Return dedupe key — always cve_id for NVD records."""
        return record.get("cve_id") or ""
