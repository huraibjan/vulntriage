"""Asset inventory, SBOM/VEX ingestion and per-asset finding queues."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.security import require_api_key
from app.core.logging import get_logger
from app.db.asset_models import Asset, AssetSoftwareObs, DecisionObs, VexStatementObs
from app.db.session import get_db
from app.schemas.asset_schemas import AssetCreate

log = get_logger(__name__)
router = APIRouter()

# Uploaded documents are parsed in memory; bound their size.
MAX_COMPONENTS = 20000


def _asset_or_404(asset_id: str, db: Session) -> Asset:
    try:
        uid = UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")
    asset = db.query(Asset).filter_by(id=uid).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")
    return asset


def _asset_payload(asset: Asset, db: Session) -> Dict[str, Any]:
    components = (
        db.query(func.count(AssetSoftwareObs.id)).filter_by(asset_id=asset.id).scalar() or 0
    )
    by_action = dict(
        db.query(DecisionObs.action, func.count(DecisionObs.id))
        .filter(DecisionObs.asset_id == asset.id)
        .group_by(DecisionObs.action)
        .all()
    )
    return {
        "id": str(asset.id),
        "name": asset.name,
        "asset_type": asset.asset_type,
        "environment": asset.environment,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "is_internet_facing": asset.is_internet_facing,
        "network_zone": asset.network_zone,
        "tags": asset.tags_json,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "components": components,
        "findings_by_action": by_action,
        "urgent": by_action.get("patch_now", 0) + by_action.get("mitigate_now", 0),
    }


@router.get("/v1/assets")
def list_assets(db: Session = Depends(get_db)):
    """All assets with inventory size and finding counts."""
    assets = db.query(Asset).order_by(Asset.created_at.desc()).all()
    return {"items": [_asset_payload(a, db) for a in assets], "total": len(assets)}


@router.post("/v1/assets", status_code=201, dependencies=[Depends(require_api_key)])
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    """Register an asset."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Asset name must not be empty")

    def val(x):
        return getattr(x, "value", x)

    asset = Asset(
        name=name[:256],
        asset_type=val(payload.asset_type),
        environment=val(payload.environment),
        criticality=val(payload.criticality),
        owner=payload.owner,
        is_internet_facing=payload.is_internet_facing,
        network_zone=payload.network_zone,
        tags_json=payload.tags,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return _asset_payload(asset, db)


@router.get("/v1/assets/{asset_id}")
def get_asset(asset_id: str, db: Session = Depends(get_db)):
    return _asset_payload(_asset_or_404(asset_id, db), db)


@router.delete("/v1/assets/{asset_id}", dependencies=[Depends(require_api_key)])
def delete_asset(asset_id: str, db: Session = Depends(get_db)):
    """Remove an asset with its inventory, VEX statements and decisions."""
    asset = _asset_or_404(asset_id, db)
    db.query(VexStatementObs).filter_by(asset_id=asset.id).delete(synchronize_session=False)
    db.delete(asset)
    db.commit()
    return {"deleted": asset_id}


@router.get("/v1/assets/{asset_id}/components")
def list_components(
    asset_id: str,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    asset = _asset_or_404(asset_id, db)
    rows = (
        db.query(AssetSoftwareObs)
        .filter_by(asset_id=asset.id)
        .order_by(AssetSoftwareObs.product)
        .limit(limit)
        .all()
    )
    return {
        "items": [
            {
                "vendor": r.vendor, "product": r.product, "version": r.version,
                "cpe": r.cpe, "purl": r.purl,
                "identity_confidence": r.confidence, "source": r.source,
            }
            for r in rows
        ]
    }


@router.post("/v1/assets/{asset_id}/sbom", dependencies=[Depends(require_api_key)])
def upload_sbom(
    asset_id: str,
    document: Dict[str, Any] = Body(..., description="CycloneDX or SPDX JSON document"),
    evaluate: bool = Query(True, description="Recompute the finding queue after import"),
    db: Session = Depends(get_db),
):
    """Import an SBOM as the asset's software inventory and rebuild its queue."""
    from app.features.asset_findings import evaluate_asset
    from app.ingest.sbom_provider import ingest_sbom_data

    asset = _asset_or_404(asset_id, db)
    n = len(document.get("components") or document.get("packages") or [])
    if n > MAX_COMPONENTS:
        raise HTTPException(status_code=413, detail=f"SBOM exceeds {MAX_COMPONENTS} components")
    try:
        imported = ingest_sbom_data(document, asset.id, db)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    result: Dict[str, Any] = {"sbom": imported}
    if evaluate:
        result["evaluation"] = evaluate_asset(asset, db)
    return result


@router.post("/v1/assets/{asset_id}/vex", dependencies=[Depends(require_api_key)])
def upload_vex(
    asset_id: str,
    document: Dict[str, Any] = Body(..., description="OpenVEX or CSAF VEX JSON document"),
    evaluate: bool = Query(True),
    db: Session = Depends(get_db),
):
    """Import VEX statements scoped to this asset and rebuild its queue."""
    from app.features.asset_findings import evaluate_asset
    from app.ingest.sbom_provider import ingest_vex_data

    asset = _asset_or_404(asset_id, db)
    try:
        imported = ingest_vex_data(document, db, asset_id=asset.id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    result: Dict[str, Any] = {"vex": imported}
    if evaluate:
        result["evaluation"] = evaluate_asset(asset, db)
    return result


@router.post("/v1/assets/{asset_id}/evaluate", dependencies=[Depends(require_api_key)])
def evaluate(
    asset_id: str,
    asof: Optional[str] = Query(None, description="As-of date YYYY-MM-DD"),
    db: Session = Depends(get_db),
):
    """Recompute the finding queue for an asset."""
    from app.features.asset_findings import evaluate_asset

    asset = _asset_or_404(asset_id, db)
    asof_date = date.fromisoformat(asof) if asof else datetime.utcnow().date()
    return evaluate_asset(asset, db, asof_date)


@router.get("/v1/assets/{asset_id}/findings")
def findings(
    asset_id: str,
    action: Optional[str] = Query(None, description="Filter by action tier"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Prioritised findings for an asset, most urgent first."""
    from app.features.asset_findings import list_findings

    asset = _asset_or_404(asset_id, db)
    return list_findings(asset, db, action=action, limit=limit, offset=offset)
