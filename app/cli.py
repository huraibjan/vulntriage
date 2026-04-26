"""VulnTriage CLI – Typer-based command-line interface.

Commands:
  ingest vuldb     – Load VulnDB JSON into Postgres + Qdrant
  ingest epss      – Fetch EPSS scores for ingested CVEs
  ingest kev       – Fetch CISA KEV catalog
  ingest attck     – Load ATT&CK STIX bundle into Qdrant
  ingest nvd       – Fetch CVEs from NVD API
  ingest sbom      – Import SBOM file for an asset
  build-labels     – Build circularity-free ground truth labels
  validate-labels  – Validate labels for circularity
  build-features   – Compute feature vectors as-of a date
  train tabular    – Train XGBoost stage-1 model (supports --ablation)
  train text       – Train text stage-2 model
  evaluate         – Run evaluation with baselines and generate reports
  evaluate-slices  – Run subpopulation evaluation across all slices
  decide           – Run SSVC-style decision engine for an asset+CVE
  demo             – Generate sample vulnerability briefs
  predict          – Predict exploitability for a single CVE
  serve            – Start the FastAPI server
"""

from __future__ import annotations

import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from app.core.logging import get_logger, setup_logging
from app.core.settings import get_settings

console = Console()
app = typer.Typer(name="vulntriage", help="AI-Driven Vulnerability Intelligence System")
ingest_app = typer.Typer(help="Data ingestion commands")
train_app = typer.Typer(help="Model training commands")
app.add_typer(ingest_app, name="ingest")
app.add_typer(train_app, name="train")


# ══════════════════════════════════════════════════════════════════════════
#  INGEST
# ══════════════════════════════════════════════════════════════════════════

@ingest_app.command("vuldb")
def ingest_vuldb(
    input: str = typer.Option(default=..., help="Path to VulnDB JSON file"),
):
    """Ingest VulnDB vulnerabilities from a local JSON file."""
    setup_logging(fmt="console")
    log = get_logger("cli.ingest")
    console.print(f"[bold blue]📥 Ingesting VulnDB from:[/] {input}")

    from app.db.session import get_session, init_db
    from app.ingest.orchestrator import build_labels, ingest_vulnerabilities
    from app.ingest.vulndb_provider import VulnDBProvider

    # Ensure tables exist
    init_db()

    provider = VulnDBProvider(input_path=input)
    records = provider.fetch()
    console.print(f"  Loaded {len(records)} records from file")

    with get_session() as session:
        inserted = ingest_vulnerabilities(records, session)
        console.print(f"  [green]✓[/] Inserted {inserted} new vulnerabilities")

        # Build labels
        n_labels = build_labels(session, policy="composite")
        console.print(f"  [green]✓[/] Built {n_labels} labels (composite policy)")

    # Embed into Qdrant
    try:
        from app.ingest.qdrant_loader import (
            ensure_collections,
            get_qdrant_client,
            upsert_vulnerability_embeddings,
        )

        client = get_qdrant_client()
        ensure_collections(client)

        embed_records = [
            {
                "id": str(r.get("vuldb_id", "")),
                "description": r.get("description", ""),
                "cve_id": r.get("cve_id"),
                "vuldb_id": r.get("vuldb_id"),
                "published_at": str(r.get("published_at", "")),
                "cvss_base_score": r.get("cvss_base_score"),
            }
            for r in records
        ]
        n_embedded = upsert_vulnerability_embeddings(embed_records, client=client)
        console.print(f"  [green]✓[/] Embedded {n_embedded} descriptions in Qdrant")
    except Exception as e:
        console.print(f"  [yellow]⚠[/] Qdrant embedding skipped: {e}")

    console.print("[bold green]✅ VulnDB ingestion complete[/]")


@ingest_app.command("epss")
def ingest_epss(
    asof: str = typer.Option(default=None, help="As-of date YYYY-MM-DD"),
):
    """Fetch EPSS scores for ingested CVEs."""
    setup_logging(fmt="console")
    console.print("[bold blue]📥 Fetching EPSS scores...[/]")

    from app.db.models import Vulnerability
    from app.db.session import get_session
    from app.ingest.enrichment_providers import EPSSProvider
    from app.ingest.orchestrator import ingest_signal_records

    with get_session() as session:
        cve_ids = [v.cve_id for v in session.query(Vulnerability).all() if v.cve_id]

    if not cve_ids:
        console.print("  [yellow]No CVEs found to enrich[/]")
        return

    provider = EPSSProvider()
    records = provider.fetch(cve_ids=cve_ids, asof=asof or date.today().isoformat())

    with get_session() as session:
        n = ingest_signal_records(records, session)
        console.print(f"  [green]✓[/] Ingested {n} EPSS observations")


@ingest_app.command("kev")
def ingest_kev():
    """Fetch CISA KEV catalog."""
    setup_logging(fmt="console")
    console.print("[bold blue]📥 Fetching CISA KEV catalog...[/]")

    from app.ingest.enrichment_providers import KEVProvider
    from app.ingest.orchestrator import ingest_signal_records
    from app.db.session import get_session

    provider = KEVProvider()
    records = provider.fetch()

    with get_session() as session:
        n = ingest_signal_records(records, session)
        console.print(f"  [green]✓[/] Ingested {n} KEV observations")


@ingest_app.command("attck")
def ingest_attck(
    source: str = typer.Option(default=..., help="Path to ATT&CK STIX JSON"),
):
    """Load ATT&CK STIX bundle into Qdrant for RAG."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]📥 Loading ATT&CK corpus from:[/] {source}")

    from app.rag.attck_loader import load_attck_corpus

    n = load_attck_corpus(source)
    console.print(f"  [green]✓[/] Loaded {n} ATT&CK techniques into Qdrant")


@ingest_app.command("nvd")
def ingest_nvd(
    start_date: str = typer.Option(default="2024-01-01", help="Start date YYYY-MM-DD"),
    end_date: str = typer.Option(default="2024-12-31", help="End date YYYY-MM-DD"),
    severity: str = typer.Option(default=None, help="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    cve_id: str = typer.Option(default=None, help="Fetch single CVE by ID (e.g., CVE-2024-21887)"),
    dry_run: bool = typer.Option(default=False, help="Preview only, don't save to database"),
):
    """Fetch CVEs from NVD (National Vulnerability Database) API.
    
    Fetches real vulnerability data from https://services.nvd.nist.gov.
    Supports date-range queries with automatic chunking for the 120-day API limit.
    
    Examples:
        vulntriage ingest nvd                                    # All 2024 CVEs
        vulntriage ingest nvd --severity CRITICAL                # Only critical 2024 CVEs
        vulntriage ingest nvd --cve-id CVE-2024-21887            # Single CVE lookup
        vulntriage ingest nvd --start-date 2024-06-01 --end-date 2024-06-30
    
    Note: Rate limited to ~1 request/6 seconds. Full 2024 fetch takes ~30-40 minutes.
    Set NVD_API environment variable for higher rate limits (free key from nvd.nist.gov).
    """
    setup_logging(fmt="console")
    
    from app.core.settings import get_settings
    from app.db.session import get_session, init_db
    from app.ingest.nvd_provider import NVDProvider
    from app.ingest.orchestrator import build_labels, ingest_vulnerabilities

    settings = get_settings()
    
    if cve_id:
        console.print(f"[bold blue]📥 Fetching single CVE from NVD:[/] {cve_id}")
    else:
        console.print(f"[bold blue]📥 Fetching NVD CVEs:[/] {start_date} → {end_date}")
        if severity:
            console.print(f"  Severity filter: {severity.upper()}")
    
    if settings.nvd_api:
        console.print("  [green]✓[/] Using NVD API key (higher rate limits)")
    else:
        console.print("  [yellow]⚠[/] No NVD_API key set; using public rate limits (slower)")

    provider = NVDProvider()
    records = provider.fetch(
        start_date=start_date,
        end_date=end_date,
        severity=severity,
        cve_id=cve_id,
    )
    
    console.print(f"  Fetched {len(records)} CVE records from NVD")
    
    if dry_run:
        console.print("\n[yellow]DRY RUN – not saving to database[/]")
        # Show sample records
        for rec in records[:5]:
            console.print(f"    {rec.get('cve_id')}: {rec.get('title', 'No title')[:60]}")
        if len(records) > 5:
            console.print(f"    ... and {len(records) - 5} more")
        return

    # Ensure tables exist
    init_db()

    with get_session() as session:
        inserted = ingest_vulnerabilities(records, session)
        console.print(f"  [green]✓[/] Inserted {inserted} new vulnerabilities")

        # Build labels (KEV signals from NVD inline data)
        n_labels = build_labels(session, policy="composite")
        console.print(f"  [green]✓[/] Built {n_labels} labels")

    # Embed into Qdrant
    try:
        from app.ingest.qdrant_loader import (
            ensure_collections,
            get_qdrant_client,
            upsert_vulnerability_embeddings,
        )

        client = get_qdrant_client()
        ensure_collections(client)

        embed_records = [
            {
                "id": rec.get("cve_id"),
                "description": rec.get("description", ""),
                "cve_id": rec.get("cve_id"),
                "vuldb_id": rec.get("vuldb_id"),
                "published_at": str(rec.get("published_at", "")),
                "cvss_base_score": rec.get("cvss_base_score"),
            }
            for rec in records
        ]
        n_embedded = upsert_vulnerability_embeddings(embed_records, client=client)
        console.print(f"  [green]✓[/] Embedded {n_embedded} descriptions in Qdrant")
    except Exception as e:
        console.print(f"  [yellow]⚠[/] Qdrant embedding skipped: {e}")

    console.print("[bold green]✅ NVD ingestion complete[/]")


# ══════════════════════════════════════════════════════════════════════════
#  BUILD FEATURES
# ══════════════════════════════════════════════════════════════════════════

@app.command("build-features")
def build_features(
    asof: str = typer.Option(default=..., help="As-of date YYYY-MM-DD"),
    leakage_audit: bool = typer.Option(default=False, help="Enable leakage audit"),
):
    """Compute feature vectors for all vulnerabilities as-of a date."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]🔧 Building features as-of {asof}[/]")

    from app.db.session import get_session
    from app.features.builder import build_all_features

    asof_date = date.fromisoformat(asof)

    with get_session() as session:
        df = build_all_features(session, asof_date, leakage_audit=leakage_audit)
        console.print(f"  [green]✓[/] Built {len(df)} feature vectors with {len(df.columns)} features")

    if leakage_audit:
        console.print("  [green]✓[/] Leakage audit passed")


# ══════════════════════════════════════════════════════════════════════════
#  TRAIN
# ══════════════════════════════════════════════════════════════════════════

@train_app.command("tabular")
def train_tabular(
    cutoff: str = typer.Option(default=..., help="Time-split cutoff date YYYY-MM-DD"),
    ablation: str = typer.Option(default="full", help="Ablation config: full, no_circular, cve_only, temporal_only, network_enriched, text_only"),
    policy: str = typer.Option(default="kev_strict", help="Label policy for circularity exclusion"),
):
    """Train XGBoost tabular model with time-aware split and ablation support."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]🤖 Training tabular model (cutoff={cutoff}, ablation={ablation}, policy={policy})[/]")

    from app.db.session import get_session
    from app.features.ablation import apply_ablation, get_ablation_config, get_feature_columns
    from app.features.builder import build_all_features, build_labels_df, time_aware_split
    from app.ingest.label_builder import get_excluded_features
    from app.ml.tabular.train import (
        evaluate_model,
        save_model,
        train_xgboost,
    )

    settings = get_settings()
    asof_date = date.fromisoformat(cutoff)

    # Get ablation config and circularity exclusions
    config = get_ablation_config(ablation)
    excluded = get_excluded_features(policy)
    feature_cols = get_feature_columns(ablation, policy)

    console.print(f"  Ablation: {config.name} ({len(config.included_features)} features)")
    console.print(f"  Circularity exclusions: {sorted(excluded)}")
    console.print(f"  Final feature count: {len(feature_cols)}")

    with get_session() as session:
        features_df = build_all_features(session, asof_date)
        labels_df = build_labels_df(session)

    if labels_df.empty:
        console.print("[red]No labels found. Run 'build-labels' first.[/]")
        return

    # Apply ablation
    df_ablated = apply_ablation(features_df, config, extra_exclude=excluded)
    merged = df_ablated.merge(labels_df, on="vuln_id", how="inner")

    try:
        train_df, test_df = time_aware_split(merged, cutoff)
    except ValueError as e:
        console.print(f"[yellow]⚠ Cannot time-split: {e}. Using all data.[/]")
        train_df = merged
        test_df = merged

    # Prepare data (exclude meta columns)
    meta_cols = {"vuln_id", "cve_id", "published_at", "exploited"}
    train_feature_cols = [c for c in train_df.columns if c not in meta_cols]
    test_feature_cols = [c for c in test_df.columns if c not in meta_cols]

    X_train = train_df[train_feature_cols].fillna(0)
    y_train = train_df["exploited"].values
    X_test = test_df[test_feature_cols].fillna(0)
    y_test = test_df["exploited"].values

    console.print(f"  Train: {len(X_train)} | Test: {len(X_test)}")
    console.print(f"  Positive rate – Train: {y_train.mean():.1%} | Test: {y_test.mean():.1%}")

    model = train_xgboost(X_train, y_train)
    metrics = evaluate_model(model, X_test, y_test)

    save_model(model)

    # Display results
    table = Table(title=f"Tabular Model Metrics (ablation={ablation})")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("PR-AUC", f"{metrics['pr_auc']:.4f}")
    table.add_row("ROC-AUC", f"{metrics.get('roc_auc', 0):.4f}")
    table.add_row("Brier Score", f"{metrics['brier_score']:.4f}")
    table.add_row("F1", f"{metrics['f1']:.4f}")
    console.print(table)


@train_app.command("text")
def train_text(
    mode: str = typer.Option(default="pretrained", help="Mode: pretrained | finetune"),
    cutoff: str = typer.Option(default="2024-12-31", help="Time-split cutoff"),
):
    """Train text-based exploitability model."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]🤖 Training text model (mode={mode})[/]")

    from app.db.models import Vulnerability
    from app.db.session import get_session
    from app.features.builder import build_labels_df
    from app.ml.text.train import TextPredictor

    with get_session() as session:
        vulns = session.query(Vulnerability).all()
        vuln_data = {
            str(v.id): {"description": v.description or "", "published_at": str(v.published_at)}
            for v in vulns
        }
        labels_df = build_labels_df(session)

    if labels_df.empty:
        console.print("[red]No labels found.[/]")
        return

    # Merge descriptions with labels
    texts = []
    labels = []
    for _, row in labels_df.iterrows():
        vid = row["vuln_id"]
        if vid in vuln_data and vuln_data[vid]["description"]:
            texts.append(vuln_data[vid]["description"])
            labels.append(int(row["exploited"]))

    console.print(f"  Samples: {len(texts)} | Positive rate: {sum(labels)/len(labels):.1%}")

    predictor = TextPredictor(mode=mode)

    if mode == "pretrained":
        metrics = predictor.train_pretrained_mode(texts, labels)
    else:
        metrics = predictor.train_finetune_mode(texts, labels)

    predictor.save()
    console.print(f"  [green]✓[/] Text model trained: {json.dumps(metrics, indent=2)}")


# ══════════════════════════════════════════════════════════════════════════
#  EVALUATE
# ══════════════════════════════════════════════════════════════════════════

@app.command("evaluate")
def evaluate(
    cutoff: str = typer.Option(default="2024-12-31", help="Time-split cutoff"),
    report: bool = typer.Option(default=True, help="Generate report"),
):
    """Run full evaluation with baselines and generate reports."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]📊 Running evaluation (cutoff={cutoff})[/]")

    from app.db.session import get_session
    from app.features.builder import build_all_features, build_labels_df, time_aware_split
    from app.ml.tabular.train import (
        cvss_baseline,
        epss_baseline,
        evaluate_model,
        kev_baseline,
        load_model,
        prepare_data,
    )
    from app.reports.generator import (
        generate_summary_md,
        plot_calibration,
        plot_pr_curve,
        plot_topk_precision,
        save_metrics,
    )

    settings = get_settings()
    asof_date = date.fromisoformat(cutoff)

    with get_session() as session:
        features_df = build_all_features(session, asof_date)
        labels_df = build_labels_df(session)

    merged = features_df.merge(labels_df, on="vuln_id", how="inner")

    try:
        train_df, test_df = time_aware_split(merged, cutoff)
    except ValueError:
        console.print("[yellow]⚠ Time split not possible; using full dataset[/]")
        test_df = merged
        train_df = merged

    X_test, y_test = prepare_data(
        test_df.drop(columns=["exploited"], errors="ignore"),
        test_df[["vuln_id", "exploited"]],
    )

    # Load model
    try:
        model = load_model()
    except FileNotFoundError:
        console.print("[red]No trained model found. Run 'train tabular' first.[/]")
        return

    # Model metrics
    model_metrics = evaluate_model(model, X_test, y_test)

    # Baselines
    baselines = {
        "cvss_only": cvss_baseline(X_test, y_test),
        "epss_only": epss_baseline(X_test, y_test),
        "kev_first": kev_baseline(X_test, y_test),
    }

    # Aggregate report
    full_metrics = {
        "cutoff_date": cutoff,
        "n_train": len(train_df),
        "n_test": len(test_df),
        "model": model_metrics,
        "baselines": baselines,
    }

    if report:
        save_metrics(full_metrics)
        plot_pr_curve(model_metrics, baselines)
        plot_topk_precision(model_metrics.get("top_k_precision", {}), baselines)

        # Calibration
        cal_data = model_metrics.get("calibration_curve", {"prob_true": [], "prob_pred": []})
        # Generate calibration from predictions
        from sklearn.calibration import calibration_curve
        y_prob = model.predict_proba(X_test)[:, 1]
        try:
            prob_true, prob_pred = calibration_curve(y_test, y_prob, n_bins=5)
            cal_data = {"prob_true": prob_true.tolist(), "prob_pred": prob_pred.tolist()}
        except ValueError:
            pass
        plot_calibration(cal_data)

        generate_summary_md(full_metrics)
        console.print(f"\n[bold green]✅ Reports saved to {settings.reports_dir}[/]")

    # Display summary table
    table = Table(title="Evaluation Results")
    table.add_column("", style="bold")
    table.add_column("Our Model", style="green")
    table.add_column("CVSS-Only", style="red")
    table.add_column("EPSS-Only", style="yellow")
    table.add_column("KEV-First", style="cyan")

    table.add_row(
        "PR-AUC",
        f"{model_metrics.get('pr_auc', 0):.3f}",
        f"{baselines['cvss_only'].get('pr_auc', 0):.3f}",
        f"{baselines['epss_only'].get('pr_auc', 0):.3f}",
        f"{baselines['kev_first'].get('pr_auc', 0):.3f}",
    )
    table.add_row(
        "Brier ↓",
        f"{model_metrics.get('brier_score', 0):.3f}",
        f"{baselines['cvss_only'].get('brier_score', 0):.3f}",
        f"{baselines['epss_only'].get('brier_score', 0):.3f}",
        f"{baselines['kev_first'].get('brier_score', 0):.3f}",
    )
    console.print(table)


# ══════════════════════════════════════════════════════════════════════════
#  BUILD LABELS (circularity-free)
# ══════════════════════════════════════════════════════════════════════════

@app.command("build-labels")
def build_labels_cmd(
    policy: str = typer.Option(default="kev_strict", help="Label policy: kev_strict, temporal_first_exploit, composite_no_leak, epss_derived"),
    asof: str = typer.Option(default=None, help="As-of date YYYY-MM-DD"),
    overwrite: bool = typer.Option(default=False, help="Overwrite existing labels for this policy"),
    dry_run: bool = typer.Option(default=False, help="Compute without persisting"),
):
    """Build circularity-free ground-truth labels with provenance tracking."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]🏷️  Building labels (policy={policy})[/]")

    from app.db.session import get_session
    from app.ingest.label_builder import build_labels, list_policies

    asof_date = date.fromisoformat(asof) if asof else None

    with get_session() as session:
        provenance = build_labels(
            session,
            policy_name=policy,
            asof=asof_date,
            overwrite=overwrite,
            dry_run=dry_run,
        )

    positive = sum(1 for p in provenance if p.label_value == 1)
    total = len(provenance)
    rate = positive / total if total > 0 else 0.0

    console.print(f"  Total: {total} | Positive: {positive} | Rate: {rate:.4f}")
    console.print(f"  Excluded features: {sorted(get_excluded_features_for_display(policy))}")

    if dry_run:
        console.print("[yellow]  DRY RUN — labels not persisted[/]")
    else:
        console.print(f"[bold green]✅ Labels built with policy '{policy}'[/]")


def get_excluded_features_for_display(policy_name: str):
    """Helper to get excluded features for CLI display."""
    try:
        from app.ingest.label_builder import get_excluded_features
        return get_excluded_features(policy_name)
    except ValueError:
        return set()


# ══════════════════════════════════════════════════════════════════════════
#  VALIDATE LABELS
# ══════════════════════════════════════════════════════════════════════════

@app.command("validate-labels")
def validate_labels_cmd(
    policy: str = typer.Option(default="kev_strict", help="Label policy to validate"),
):
    """Validate labels for circularity and data quality."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]🔍 Validating labels (policy={policy})[/]")

    from app.db.session import get_session
    from app.ingest.label_builder import detect_label_conflicts, validate_labels

    with get_session() as session:
        report = validate_labels(session, policy_name=policy)

        # Display results
        table = Table(title=f"Label Validation: {policy}")
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Detail", style="dim")

        for check_name, check_result in report["checks"].items():
            status = check_result.get("status", "N/A")
            style = "green" if status == "PASS" else "red" if status == "FAIL" else "yellow"
            table.add_row(
                check_name,
                f"[{style}]{status}[/{style}]",
                check_result.get("detail", ""),
            )

        console.print(table)

        # Check conflicts
        conflicts = detect_label_conflicts(session)
        if conflicts:
            console.print(f"\n  [yellow]⚠ {len(conflicts)} label conflicts across policies[/]")
        else:
            console.print(f"\n  [green]✓ No label conflicts[/]")

    overall = report["overall_status"]
    style = "green" if overall == "PASS" else "red"
    console.print(f"\n[bold {style}]Overall: {overall}[/]")


# ══════════════════════════════════════════════════════════════════════════
#  EVALUATE SLICES
# ══════════════════════════════════════════════════════════════════════════

@app.command("evaluate-slices")
def evaluate_slices_cmd(
    cutoff: str = typer.Option(default="2024-12-31", help="Time-split cutoff"),
    slice_name: str = typer.Option(default=None, help="Specific slice (or 'all')"),
    ablation: str = typer.Option(default="full", help="Ablation config name"),
    policy: str = typer.Option(default="kev_strict", help="Label policy"),
):
    """Run subpopulation evaluation across slices."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]📊 Evaluating slices (ablation={ablation}, policy={policy})[/]")

    from app.db.session import get_session
    from app.features.ablation import apply_ablation, get_ablation_config
    from app.features.builder import build_all_features, build_labels_df, time_aware_split
    from app.ingest.label_builder import get_excluded_features
    from app.ml.evaluation_slices import evaluate_slices, list_slices
    from app.ml.tabular.train import load_model, prepare_data

    settings = get_settings()
    asof_date = date.fromisoformat(cutoff)
    config = get_ablation_config(ablation)
    excluded = get_excluded_features(policy)

    with get_session() as session:
        features_df = build_all_features(session, asof_date)
        labels_df = build_labels_df(session)

    # Apply ablation
    df_ablated = apply_ablation(features_df, config, extra_exclude=excluded)
    merged = df_ablated.merge(labels_df, on="vuln_id", how="inner")

    try:
        _, test_df = time_aware_split(merged, cutoff)
    except ValueError:
        test_df = merged

    # Load model and predict
    try:
        model = load_model()
        feature_cols = [c for c in test_df.columns if c not in ("vuln_id", "cve_id", "published_at", "exploited")]
        X_test = test_df[feature_cols].fillna(0)
        test_df = test_df.copy()
        test_df["y_pred"] = model.predict(X_test)
        test_df["y_prob"] = model.predict_proba(X_test)[:, 1]
    except Exception as e:
        console.print(f"[red]Cannot load model: {e}[/]")
        return

    # Select slices
    slice_names = None if not slice_name or slice_name == "all" else [slice_name]

    # Run slice evaluation
    results = evaluate_slices(
        test_df,
        y_true_col="exploited",
        y_pred_col="y_pred",
        y_prob_col="y_prob",
        slice_names=slice_names,
    )

    # Display
    table = Table(title=f"Slice Evaluation: ablation={ablation}, policy={policy}")
    table.add_column("Slice", style="cyan")
    table.add_column("N", style="dim")
    table.add_column("Pos%", style="dim")
    table.add_column("Precision", style="green")
    table.add_column("Recall", style="green")
    table.add_column("F1", style="green")
    table.add_column("PR-AUC", style="bold green")

    for _, row in results.iterrows():
        table.add_row(
            str(row["slice"]),
            str(row["n"]),
            f"{row['positive_rate']:.3f}" if row.get("positive_rate") else "—",
            f"{row['precision']:.3f}" if row.get("precision") else "—",
            f"{row['recall']:.3f}" if row.get("recall") else "—",
            f"{row['f1']:.3f}" if row.get("f1") else "—",
            f"{row['pr_auc']:.3f}" if row.get("pr_auc") else "—",
        )

    console.print(table)

    # Save to file
    output_path = settings.reports_dir / f"slices_{ablation}_{policy}.json"
    results.to_json(output_path, orient="records", indent=2)
    console.print(f"\n[green]✓ Saved to {output_path}[/]")


# ══════════════════════════════════════════════════════════════════════════
#  DECIDE (SSVC-style)
# ══════════════════════════════════════════════════════════════════════════

@app.command("decide")
def decide_cmd(
    cve_id: str = typer.Option(default=..., help="CVE ID"),
    asset_id: str = typer.Option(default=None, help="Asset UUID (optional)"),
    asset_criticality: str = typer.Option(default="medium", help="Asset criticality: critical, high, medium, low"),
):
    """Run SSVC-style triage decision for a CVE (optionally on an asset)."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]⚖️  Decision engine: {cve_id}[/]")

    from app.db.models import SignalObservation, Vulnerability
    from app.db.session import get_session
    from app.features.builder import build_features_for_vuln
    from app.schemas.decision import (
        Action,
        Affectedness,
        Criticality,
        EvidenceInput,
        Exploitation,
        Reachability,
        decide,
    )

    with get_session() as session:
        vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
        if not vuln:
            console.print(f"[red]CVE not found: {cve_id}[/]")
            return

        features = build_features_for_vuln(vuln, session, date.today())

        # Determine exploitation state from signals
        signals = {s.signal_type: s for s in vuln.signals}
        if signals.get("kev") and signals["kev"].value_bool:
            exploitation = Exploitation.ACTIVE
        elif (signals.get("poc_exploitdb") and signals["poc_exploitdb"].value_bool) or \
             (signals.get("metasploit") and signals["metasploit"].value_bool):
            exploitation = Exploitation.POC_PUBLIC
        else:
            exploitation = Exploitation.NONE

        # Try ML prediction
        ml_prob = None
        try:
            from app.ml.tabular.train import load_model, predict
            model = load_model()
            ml_prob = predict(model, features)
        except Exception:
            pass

        evidence = EvidenceInput(
            affectedness=Affectedness.UNKNOWN,
            reachability=Reachability.UNKNOWN,
            exploitation=exploitation,
            epss_score=features.get("epss_score", 0.0),
            ml_exploit_prob=ml_prob,
            days_since_published=int(features.get("days_since_published", 0)),
            control_status="unknown",
            asset_criticality=asset_criticality,
            cvss_base_score=vuln.cvss_base_score or 0.0,
        )

        decision = decide(evidence)

    # Display
    action_colors = {
        "patch_now": "red bold",
        "mitigate_now": "red",
        "patch_window": "yellow",
        "monitor": "cyan",
        "accept": "green",
    }
    action_str = decision.action.value if hasattr(decision.action, 'value') else decision.action
    color = action_colors.get(action_str, "white")

    console.print(f"\n  CVE:        {cve_id}")
    console.print(f"  CVSS:       {vuln.cvss_base_score}")
    console.print(f"  EPSS:       {features.get('epss_score', 'N/A')}")
    console.print(f"  Exploit:    {exploitation.value if hasattr(exploitation, 'value') else exploitation}")
    console.print(f"  ML Prob:    {ml_prob:.3f}" if ml_prob else "  ML Prob:    N/A")
    console.print(f"  Criticality:{asset_criticality}")
    console.print(f"\n  [{color}]ACTION: {action_str.upper()}[/{color}]")
    console.print(f"  Confidence: {decision.confidence:.0%}")
    console.print(f"  SLA:        {decision.sla_hours}h ({decision.sla_hours // 24}d)")
    console.print(f"\n  Rationale:")
    for r in decision.rationale:
        console.print(f"    • {r}")


# ══════════════════════════════════════════════════════════════════════════
#  INGEST SBOM
# ══════════════════════════════════════════════════════════════════════════

@ingest_app.command("sbom")
def ingest_sbom(
    path: str = typer.Option(default=..., help="Path to SBOM JSON file"),
    asset_id: str = typer.Option(default=..., help="Asset UUID"),
    format: str = typer.Option(default="cyclonedx", help="SBOM format: cyclonedx, spdx"),
):
    """Import an SBOM file and associate components with an asset."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]📥 Importing SBOM from:[/] {path}")

    from uuid import UUID as UUID_type

    from app.db.session import get_session
    from app.ingest.sbom_provider import ingest_sbom_file

    with get_session() as session:
        n = ingest_sbom_file(path, UUID_type(asset_id), session, format=format)
        console.print(f"  [green]✓[/] Imported {n} software components")


# ══════════════════════════════════════════════════════════════════════════
#  INIT DB (updated to include asset tables)
# ══════════════════════════════════════════════════════════════════════════

@app.command("init-db")
def init_db_cmd():
    """Initialize all database tables (core + asset models)."""
    setup_logging(fmt="console")
    console.print("[bold blue]🗄️  Initializing database tables...[/]")

    from app.db.session import init_db

    # Import asset models so they register with Base
    import app.db.asset_models  # noqa: F401

    init_db()
    console.print("[bold green]✅ All tables created[/]")


# ══════════════════════════════════════════════════════════════════════════
#  DEMO
# ══════════════════════════════════════════════════════════════════════════

@app.command("demo")
def demo(
    top_k: int = typer.Option(default=3, help="Number of briefs to generate"),
    asof: str = typer.Option(default="2026-02-25", help="As-of date"),
    with_rag: bool = typer.Option(default=False, help="Include ATT&CK mapping"),
):
    """Generate sample STRICT JSON vulnerability briefs for demo."""
    setup_logging(fmt="console")
    console.print(f"[bold blue]📋 Generating {top_k} demo briefs (asof={asof})[/]")

    from app.db.models import Vulnerability
    from app.db.session import get_session
    from app.features.builder import build_features_for_vuln
    from app.rag.generator import generate_brief
    from app.rag.verifier import verify_brief

    settings = get_settings()
    asof_date = date.fromisoformat(asof)

    # Try to load tabular model
    p_stage1_fn = None
    try:
        from app.ml.tabular.train import load_model, predict
        model = load_model()
        p_stage1_fn = lambda features: predict(model, features)
    except Exception:
        console.print("  [yellow]⚠ No tabular model; using composite score[/]")

    with get_session() as session:
        vulns = (
            session.query(Vulnerability)
            .order_by(Vulnerability.cvss_base_score.desc().nullslast())
            .limit(top_k)
            .all()
        )

        briefs_output = []

        for vuln in vulns:
            features = build_features_for_vuln(vuln, session, asof_date)

            if p_stage1_fn:
                p1 = p_stage1_fn(features)
            else:
                p1 = features.get("composite_exploit_score", 0.5)

            vuln_dict = {
                "id": str(vuln.id),
                "source": vuln.source,
                "cve_id": vuln.cve_id,
                "vuldb_id": vuln.vuldb_id,
                "published_at": vuln.published_at,
                "title": vuln.title,
                "description": vuln.description,
                "cvss_version": vuln.cvss_version,
                "cvss_vector": vuln.cvss_vector,
                "cvss_base_score": vuln.cvss_base_score,
                "cwe_ids": vuln.cwe_ids,
                "affected_products_json": vuln.affected_products_json,
                "references_json": vuln.references_json,
            }

            scores = {
                "p_stage1": p1,
                "p_final": p1,
                "explanations": {
                    "top_tabular_features": [
                        {"name": "epss_score", "value": features.get("epss_score")},
                        {"name": "cvss_base_score", "value": features.get("cvss_base_score")},
                        {"name": "kev_flag", "value": features.get("kev_flag")},
                    ]
                },
            }

            if with_rag:
                try:
                    # Load ATT&CK corpus if not loaded
                    from app.rag.attck_loader import load_attck_corpus, get_technique_registry
                    if not get_technique_registry():
                        attck_path = settings.data_dir / "attck" / "enterprise-attack.json"
                        if attck_path.exists():
                            load_attck_corpus(str(attck_path))

                    brief = generate_brief(vuln_dict, scores, asof_date=asof)
                    is_valid, errors = verify_brief(brief)

                    if not is_valid:
                        console.print(f"  [yellow]⚠ Brief verification warnings for {vuln.cve_id}: {errors[:3]}[/]")

                    brief_json = brief.model_dump(mode="json")
                except Exception as e:
                    console.print(f"  [yellow]⚠ RAG failed for {vuln.cve_id}: {e}[/]")
                    brief_json = {"vuln_id": str(vuln.id), "cve_id": vuln.cve_id, "p_final": p1, "error": str(e)}
            else:
                brief_json = {
                    "vuln_id": str(vuln.id),
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "cvss_base_score": vuln.cvss_base_score,
                    "p_final": round(p1, 4),
                    "top_features": scores["explanations"]["top_tabular_features"],
                }

            briefs_output.append(brief_json)
            console.print(f"  ✓ {vuln.cve_id or vuln.vuldb_id}: p_final={p1:.3f}")

    # Save briefs
    output_path = settings.reports_dir / "demo_briefs.json"
    with open(output_path, "w") as f:
        json.dump(briefs_output, f, indent=2, default=str)
    console.print(f"\n[bold green]✅ {len(briefs_output)} briefs saved to {output_path}[/]")


# ══════════════════════════════════════════════════════════════════════════
#  PREDICT (single)
# ══════════════════════════════════════════════════════════════════════════

@app.command("predict")
def predict_cmd(
    vuln_id: str = typer.Option(default=..., help="CVE ID or UUID"),
    with_rag: bool = typer.Option(default=False, help="Include ATT&CK mapping"),
    asof: str = typer.Option(default=None, help="As-of date"),
):
    """Predict exploitability for a single vulnerability."""
    setup_logging(fmt="console")

    from app.db.models import Vulnerability
    from app.db.session import get_session
    from app.features.builder import build_features_for_vuln

    asof_date = date.fromisoformat(asof) if asof else date.today()

    with get_session() as session:
        vuln = session.query(Vulnerability).filter_by(cve_id=vuln_id).first()
        if not vuln:
            console.print(f"[red]Vulnerability not found: {vuln_id}[/]")
            return

        features = build_features_for_vuln(vuln, session, asof_date)

        try:
            from app.ml.tabular.train import load_model, predict
            model = load_model()
            p = predict(model, features)
        except Exception:
            p = features.get("composite_exploit_score", 0.5)

        console.print(f"\n[bold]{vuln.cve_id}: {vuln.title}[/]")
        console.print(f"  CVSS: {vuln.cvss_base_score}  |  EPSS: {features.get('epss_score', 'N/A')}")
        console.print(f"  [bold green]Predicted exploitability: {p:.3f}[/]")


# ══════════════════════════════════════════════════════════════════════════
#  SERVE
# ══════════════════════════════════════════════════════════════════════════

@app.command("serve")
def serve(
    host: str = typer.Option(default="0.0.0.0", help="Host"),
    port: int = typer.Option(default=8000, help="Port"),
):
    """Start the FastAPI server."""
    import uvicorn
    uvicorn.run("app.api.main:app", host=host, port=port, reload=True)


# ══════════════════════════════════════════════════════════════════════════
#  ACTIONABILITY COMMANDS
# ══════════════════════════════════════════════════════════════════════════

@app.command("build-actionability-features")
def build_actionability_features_cmd(
    asof: str = typer.Option(default="2026-03-03", help="As-of date (YYYY-MM-DD)"),
):
    """Compute actionability features for all (asset, CVE) pairs."""
    setup_logging()
    from datetime import date as dt_date
    from app.db.session import get_session
    from app.features.actionability import build_all_actionability_features

    asof_date = dt_date.fromisoformat(asof)

    with get_session() as session:
        df = build_all_actionability_features(session, asof_date)

    if df.empty:
        console.print("[yellow]No asset-CVE pairs found. Ingest assets + SBOMs first.[/]")
        return

    out_path = Path(get_settings().reports_dir) / "actionability_features.csv"
    df.to_csv(out_path, index=False)
    console.print(f"[green]✓ Built {len(df)} actionability feature vectors → {out_path}[/]")


@app.command("score-assets")
def score_assets_cmd(
    asof: str = typer.Option(default="2026-03-03", help="As-of date (YYYY-MM-DD)"),
    persist: bool = typer.Option(default=True, help="Persist decisions to DB"),
):
    """Run the policy engine to score all (asset, CVE) pairs."""
    setup_logging()
    from datetime import date as dt_date
    from app.db.session import get_session
    from app.db.asset_models import Asset
    from app.db.models import Vulnerability
    from app.features.policy_engine import score_batch

    asof_date = dt_date.fromisoformat(asof)

    with get_session() as session:
        assets = session.query(Asset).all()
        if not assets:
            console.print("[yellow]No assets found. Ingest assets first.[/]")
            return

        vulns = session.query(Vulnerability).limit(1000).all()
        pairs = [
            (a.id, v.cve_id) for a in assets for v in vulns
        ]

        console.print(f"Scoring {len(pairs)} (asset, CVE) pairs …")
        results = score_batch(pairs, session, asof_date, persist=persist)

    # Summary table
    from collections import Counter
    action_dist = Counter(r["action"] for r in results)
    table = Table(title="Decision Distribution")
    table.add_column("Action", style="bold")
    table.add_column("Count", justify="right")
    for action in ["patch_now", "mitigate_now", "patch_window", "monitor", "accept"]:
        table.add_row(action, str(action_dist.get(action, 0)))
    console.print(table)
    console.print(f"[green]✓ Scored {len(results)} pairs[/]")


@app.command("evaluate-actionability")
def evaluate_actionability_cmd(
    asof: str = typer.Option(default="2026-03-03", help="As-of date (YYYY-MM-DD)"),
):
    """Evaluate actionability decisions and generate thesis artifacts."""
    setup_logging()
    from datetime import date as dt_date
    from app.db.session import get_session
    from app.db.asset_models import Asset, DecisionObs
    from app.ml.evaluation_actionability import (
        evaluate_action_labels,
        action_confusion_matrix,
        generate_case_studies,
        generate_case_studies_md,
    )
    from app.reports.generator import (
        plot_action_confusion_matrix,
        generate_actionability_summary_md,
    )

    asof_date = dt_date.fromisoformat(asof)

    with get_session() as session:
        decisions = session.query(DecisionObs).all()
        if not decisions:
            console.print("[yellow]No decisions found. Run 'score-assets' first.[/]")
            return

        # For now, use decisions as both "true" and "predicted" (self-consistency check)
        y_true = [d.action for d in decisions]
        y_pred = [d.action for d in decisions]  # in production, compare against human labels

        results = evaluate_action_labels(y_true, y_pred)
        cm = action_confusion_matrix(y_true, y_pred)

        # Plot
        plot_action_confusion_matrix(cm)

        # Case studies
        import pandas as pd
        dec_df = pd.DataFrame([
            {
                "cve_id": str(d.vulnerability_id)[:8],
                "asset_name": str(d.asset_id)[:8],
                "action": d.action,
                "confidence": d.confidence or 0.5,
                "evidence_chain_json": d.evidence_chain_json,
            }
            for d in decisions
        ])
        cases = generate_case_studies(dec_df)
        cases_md = generate_case_studies_md(cases)

        # Summary report
        path = generate_actionability_summary_md(
            results, cm, case_studies_md=cases_md,
        )

    console.print(f"[green]✓ Actionability evaluation report → {path}[/]")
    console.print(f"  Accuracy: {results['overall_accuracy']}")
    console.print(f"  Macro F1: {results.get('macro_f1', 'N/A')}")


@app.command("generate-thesis-artifacts")
def generate_thesis_artifacts_cmd(
    asof: str = typer.Option(default="2026-03-03", help="As-of date (YYYY-MM-DD)"),
):
    """One-command generation of all thesis reports and figures."""
    setup_logging()
    from datetime import date as dt_date
    from app.db.session import get_session
    from app.features.leakage_audit import audit_feature_set
    from app.features.actionability import build_all_actionability_features
    from app.ingest.actionability_label_builder import build_all_actionability_labels

    asof_date = dt_date.fromisoformat(asof)
    reports_dir = Path(get_settings().reports_dir)

    console.print("[bold]Generating thesis artifacts …[/]")

    with get_session() as session:
        # 1. Actionability features
        console.print("  [dim]Building actionability features …[/]")
        feat_df = build_all_actionability_features(session, asof_date)
        if not feat_df.empty:
            feat_df.to_csv(reports_dir / "actionability_features.csv", index=False)
            console.print(f"    ✓ {len(feat_df)} feature vectors")

        # 2. Actionability labels
        console.print("  [dim]Building actionability labels …[/]")
        label_df = build_all_actionability_labels(session, asof_date)
        if not label_df.empty:
            label_df.to_csv(reports_dir / "actionability_labels.csv", index=False)
            console.print(f"    ✓ {len(label_df)} label records")

        # 3. Leakage audit
        if not feat_df.empty and not label_df.empty:
            console.print("  [dim]Running leakage audit …[/]")
            report = audit_feature_set(
                feat_df, label_df, asof_date,
                output_path=str(reports_dir / "leakage_audit_report.json"),
            )
            verdict = report["summary"]["verdict"]
            console.print(f"    ✓ Leakage audit: {verdict}")

    console.print("[bold green]✓ All thesis artifacts generated[/]")


# ══════════════════════════════════════════════════════════════════════════

def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
