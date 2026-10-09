"""Strict point-in-time lower bound: PIT EPSS + drop accumulating counters
(reference_count, product_count) which remain 2026-frozen in the main PIT run.
"""
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))

from point_in_time_epss import *  # noqa

t0 = time.time()
snaps = load_snapshots()
cutoff_snap = snaps[sorted(snaps.keys())[0]]

with get_session() as session:
    db_snaps = session.query(FeatureSnapshot).filter_by(
        asof=ASOF_DATE, feature_version="v1").all()
    rows = []
    for s in db_snaps:
        feat = dict(s.features_json)
        feat["vuln_id"] = str(s.vulnerability_id)
        rows.append(feat)
    fdf = pd.DataFrame(rows)
    labels = build_labels_df(session, policy_name=POLICY)
    merged = fdf.merge(labels, on="vuln_id", how="inner")
    train_full, test_df = time_aware_split(merged, CUTOFF_DATE)
    y_full = train_full["exploited"].astype(int)
    train_df, val_df = train_test_split(train_full, test_size=VAL_FRACTION,
                                        stratify=y_full, random_state=SEED)
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    need = train_df["vuln_id"].tolist() + test_df["vuln_id"].tolist()
    import uuid as uuid_mod
    cve_map = {}
    for i in range(0, len(need), 10000):
        batch = [uuid_mod.UUID(v) for v in need[i:i + 10000]]
        for vid, cve in session.query(Vulnerability.id, Vulnerability.cve_id
                                      ).filter(Vulnerability.id.in_(batch)).all():
            cve_map[str(vid)] = cve or ""

for df in (train_df, test_df):
    df["cve_id"] = df["vuln_id"].map(cve_map)

y_train = train_df["exploited"].astype(int)
y_test = test_df["exploited"].astype(int).values

ep_train = train_df["cve_id"].map(cutoff_snap).fillna(0.0).values
pub = pd.to_datetime(test_df["published_at"], errors="coerce", format="ISO8601")
ep_test = pit_epss_for_test(pub, test_df["cve_id"], snaps)

feat_cols = get_feature_columns(ABLATION, policy_name=POLICY)
DROP = {"reference_count", "product_count"}
avail = [c for c in feat_cols if c in merged.columns and c not in DROP]
print(f"features: {len(avail)} (dropped {sorted(DROP)})")

def X_of(df, ep):
    X = df[avail].fillna(0).astype(float).copy()
    X["epss_score"] = ep
    return X

tab = fit_xgb(X_of(train_df, ep_train), y_train)
p_tab = tab.predict_proba(X_of(test_df, ep_test))[:, 1]
p_rrf = rrf_fuse([p_tab, ep_test], k=60)  # 2-source fallback

print(f"strict-PIT EPSS-only  PR-AUC = {pr_auc(y_test, ep_test):.5f}")
print(f"strict-PIT tabular    PR-AUC = {pr_auc(y_test, p_tab):.5f}")
print(f"strict-PIT RRF(tab,epss) PR-AUC = {pr_auc(y_test, p_rrf):.5f}")
from sklearn.metrics import roc_auc_score
print(f"strict-PIT tabular ROC = {roc_auc_score(y_test, p_tab):.5f} | EPSS ROC = {roc_auc_score(y_test, ep_test):.5f} | RRF ROC = {roc_auc_score(y_test, p_rrf):.5f}")
print(f"P@100: epss={p_at_k(y_test, ep_test, 100):.3f} tab={p_at_k(y_test, p_tab, 100):.3f} rrf={p_at_k(y_test, p_rrf, 100):.3f}")
print(f"elapsed {time.time()-t0:.0f}s")
