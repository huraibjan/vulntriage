"""SBOM / VEX ingestion provider.

Supports:
- CycloneDX JSON (v1.4, v1.5, v1.6)
- Simplified SPDX JSON
- OpenVEX JSON
- Manual CSV import

For the thesis prototype, this primarily ingests synthetic / sample data
to demonstrate the affectedness layer.  In production, it would connect
to Syft, Trivy, Grype, or an SBOM API.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.asset_models import Asset, AssetSoftwareObs, VexStatementObs
from app.db.models import Vulnerability
from app.schemas.asset_schemas import SBOMImport, SoftwareComponent, VexImport, VexStatement

log = get_logger(__name__)


# ── SBOM Ingestion ─────────────────────────────────────────────────────

def ingest_sbom_file(
    path: str,
    asset_id: UUID,
    session: Session,
    *,
    format: str = "cyclonedx",
) -> int:
    """Parse an SBOM file and create AssetSoftwareObs records.

    Parameters
    ----------
    path : str
        Path to the SBOM JSON file.
    asset_id : UUID
        Asset to associate the components with.
    session : Session
        Active SQLAlchemy session.
    format : str
        SBOM format: "cyclonedx" or "spdx".

    Returns
    -------
    int
        Number of components ingested.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"SBOM file not found: {path}")

    with open(file_path) as f:
        data = json.load(f)

    # Verify asset exists
    asset = session.query(Asset).filter_by(id=asset_id).first()
    if not asset:
        raise ValueError(f"Asset {asset_id} not found")

    if format == "cyclonedx":
        components = _parse_cyclonedx(data)
    elif format == "spdx":
        components = _parse_spdx(data)
    else:
        raise ValueError(f"Unsupported SBOM format: {format}")

    inserted = 0
    for comp in components:
        obs = AssetSoftwareObs(
            asset_id=asset_id,
            vendor=comp.vendor,
            product=comp.product,
            version=comp.version,
            cpe=comp.cpe,
            purl=comp.purl,
            install_path=comp.install_path,
            observed_at=datetime.utcnow(),
            source=comp.source,
        )
        session.add(obs)
        inserted += 1

    session.commit()
    log.info("sbom_ingested", asset_id=str(asset_id), components=inserted, format=format)
    return inserted


def _parse_cyclonedx(data: Dict[str, Any]) -> List[SoftwareComponent]:
    """Parse CycloneDX JSON into SoftwareComponent list."""
    components: List[SoftwareComponent] = []

    for comp in data.get("components", []):
        # Extract vendor from group or publisher
        vendor = comp.get("group", comp.get("publisher", "unknown"))
        product = comp.get("name", "unknown")
        version = comp.get("version")

        # Extract CPE from properties or externalReferences
        cpe = None
        for prop in comp.get("properties", []):
            if prop.get("name") == "cpe":
                cpe = prop.get("value")
                break

        # Extract PURL
        purl = comp.get("purl")

        components.append(SoftwareComponent(
            vendor=vendor,
            product=product,
            version=version,
            cpe=cpe,
            purl=purl,
            source="cyclonedx",
        ))

    return components


def _parse_spdx(data: Dict[str, Any]) -> List[SoftwareComponent]:
    """Parse simplified SPDX JSON into SoftwareComponent list."""
    components: List[SoftwareComponent] = []

    for pkg in data.get("packages", []):
        vendor = pkg.get("supplier", pkg.get("originator", "unknown"))
        product = pkg.get("name", "unknown")
        version = pkg.get("versionInfo")

        # SPDX external refs may contain CPE/PURL
        cpe = None
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "cpe23Type":
                cpe = ref.get("referenceLocator")
            elif ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")

        components.append(SoftwareComponent(
            vendor=vendor,
            product=product,
            version=version,
            cpe=cpe,
            purl=purl,
            source="spdx",
        ))

    return components


# ── VEX Ingestion ──────────────────────────────────────────────────────

def ingest_vex_file(
    path: str,
    session: Session,
    *,
    format: str = "openvex",
) -> int:
    """Parse a VEX file and create VexStatementObs records.

    Parameters
    ----------
    path : str
        Path to the VEX JSON file.
    session : Session
        Active SQLAlchemy session.
    format : str
        VEX format: "openvex" or "csaf_vex".

    Returns
    -------
    int
        Number of statements ingested.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"VEX file not found: {path}")

    with open(file_path) as f:
        data = json.load(f)

    if format == "openvex":
        statements = _parse_openvex(data)
    elif format == "csaf_vex":
        statements = _parse_csaf_vex(data)
    else:
        raise ValueError(f"Unsupported VEX format: {format}")

    inserted = 0
    for stmt in statements:
        # Look up vulnerability
        vuln = session.query(Vulnerability).filter_by(cve_id=stmt.cve_id).first()
        if not vuln:
            log.debug("vex_no_vuln", cve_id=stmt.cve_id)
            continue

        obs = VexStatementObs(
            vulnerability_id=vuln.id,
            vendor=stmt.vendor,
            product=stmt.product,
            status=stmt.status.value if hasattr(stmt.status, 'value') else stmt.status,
            justification=stmt.justification.value if stmt.justification and hasattr(stmt.justification, 'value') else stmt.justification,
            impact_statement=stmt.impact_statement,
            action_statement=stmt.action_statement,
            observed_at=datetime.utcnow(),
            source=stmt.source,
        )
        session.add(obs)
        inserted += 1

    session.commit()
    log.info("vex_ingested", statements=inserted, format=format)
    return inserted


def _parse_openvex(data: Dict[str, Any]) -> List[VexStatement]:
    """Parse OpenVEX JSON."""
    statements: List[VexStatement] = []

    for stmt in data.get("statements", []):
        vuln_id = stmt.get("vulnerability", {}).get("name", "")  # CVE ID
        if not vuln_id.startswith("CVE-"):
            # Try alternate location
            vuln_id = stmt.get("vulnerability", "")

        for product in stmt.get("products", []):
            product_id = product if isinstance(product, str) else product.get("@id", "unknown")

            statements.append(VexStatement(
                cve_id=vuln_id,
                vendor="unknown",  # OpenVEX doesn't always have vendor
                product=product_id,
                status=stmt.get("status", "under_investigation"),
                justification=stmt.get("justification"),
                impact_statement=stmt.get("impact_statement"),
                action_statement=stmt.get("action_statement"),
                source="openvex",
            ))

    return statements


def _parse_csaf_vex(data: Dict[str, Any]) -> List[VexStatement]:
    """Parse CSAF VEX JSON (simplified)."""
    statements: List[VexStatement] = []

    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cve")
        if not cve_id:
            continue

        for status_block in vuln.get("product_status", {}).items():
            status_type, product_ids = status_block
            # Map CSAF status types to VEX statuses
            status_map = {
                "known_not_affected": "not_affected",
                "known_affected": "affected",
                "fixed": "fixed",
                "under_investigation": "under_investigation",
            }
            vex_status = status_map.get(status_type, "under_investigation")

            for pid in (product_ids if isinstance(product_ids, list) else [product_ids]):
                statements.append(VexStatement(
                    cve_id=cve_id,
                    vendor="unknown",
                    product=str(pid),
                    status=vex_status,
                    source="csaf_vex",
                ))

    return statements


# ── Affectedness Matching ──────────────────────────────────────────────

def check_affectedness(
    asset_id: UUID,
    cve_id: str,
    session: Session,
) -> Dict[str, Any]:
    """Check if a CVE affects an asset based on SBOM and VEX data.

    Returns affectedness assessment with evidence.
    """
    vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
    if not vuln:
        return {
            "status": "unknown",
            "reason": f"CVE {cve_id} not found in database",
        }

    # Check VEX first (most authoritative)
    vex_statements = (
        session.query(VexStatementObs)
        .filter_by(vulnerability_id=vuln.id)
        .all()
    )

    # Check SBOM for asset
    asset_software = (
        session.query(AssetSoftwareObs)
        .filter_by(asset_id=asset_id)
        .all()
    )

    # Get affected products from vulnerability
    affected_products = vuln.affected_products_json or []

    # Match SBOM components against affected products
    sbom_match = False
    matched_component = None
    for sw in asset_software:
        for prod in affected_products:
            if (
                sw.vendor.lower() == prod.get("vendor", "").lower()
                and sw.product.lower() == prod.get("product", "").lower()
            ):
                sbom_match = True
                matched_component = {
                    "vendor": sw.vendor,
                    "product": sw.product,
                    "version": sw.version,
                    "cpe": sw.cpe,
                }
                break
        if sbom_match:
            break

    # Check VEX overrides
    for vex in vex_statements:
        if vex.status == "not_affected":
            return {
                "status": "not_affected",
                "reason": f"VEX: {vex.justification or 'vendor confirms not affected'}",
                "source": vex.source,
                "sbom_match": sbom_match,
                "matched_component": matched_component,
            }
        elif vex.status == "fixed":
            return {
                "status": "fixed",
                "reason": f"VEX: fix available — {vex.action_statement or 'update to latest version'}",
                "source": vex.source,
                "sbom_match": sbom_match,
                "matched_component": matched_component,
            }

    if sbom_match:
        return {
            "status": "affected",
            "reason": "SBOM component matches affected product",
            "matched_component": matched_component,
        }

    if not asset_software:
        return {
            "status": "unknown",
            "reason": "No SBOM data for this asset",
        }

    return {
        "status": "not_affected",
        "reason": "No SBOM component matches affected products",
        "asset_components": len(asset_software),
        "vuln_affected_products": len(affected_products),
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
