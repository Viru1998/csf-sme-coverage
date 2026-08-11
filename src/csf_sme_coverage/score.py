from __future__ import annotations

from pathlib import Path
from typing import Dict, Set

import pandas as pd

from . import ingest, filter as flt

ROOT      = Path(__file__).resolve().parents[2]
PROCESSED = ROOT / "data" / "processed"
OUTPUTS   = ROOT / "outputs"

COVERAGE_CSV = OUTPUTS / "coverage_matrix.csv"
RESIDUAL_CSV = OUTPUTS / "residual_threats.csv"
TOP20_CSV    = OUTPUTS / "top20_subcategories.csv"
SCORE_STATS  = PROCESSED / "score_stats.txt"


def compute_coverage_matrix(sme: pd.DataFrame,
                            csf: pd.DataFrame,
                            weights: pd.DataFrame) -> pd.DataFrame:
    """Return one row per CSF Subcategory with raw/weighted/unique coverage.

    Args:
        sme:     from filter.sme_bridge()
        csf:     from ingest.load_csf_subcategories()  (all 106 rows)
        weights: from ingest.load_sme_weights()

    Returns:
        DataFrame with columns
            function_code, function, category_code, category, subcategory,
            raw_coverage, weighted_coverage, unique_coverage,
            techniques_covered (semicolon-separated list, for audit)
    """
    tech_weight: Dict[str, float] = dict(
        zip(weights["technique_id"], weights["weight"])
    )

    # Subcategory -> set of techniques it addresses (post-filter)
    sub_techs: Dict[str, Set[str]] = (
        sme.groupby("subcategory")["technique_id"]
           .apply(set).to_dict()
    )

    # Technique -> set of Subcategories that cover it (for uniqueness)
    tech_subs: Dict[str, Set[str]] = (
        sme.groupby("technique_id")["subcategory"]
           .apply(set).to_dict()
    )

    rows = []
    for sub in csf["subcategory"]:
        techs = sub_techs.get(sub, set())
        raw   = len(techs)
        wgt   = round(sum(tech_weight.get(t, 0) for t in techs), 4)
        # Techniques where this Subcategory is the ONLY one covering them
        uniq  = round(
            sum(tech_weight.get(t, 0)
                for t in techs
                if len(tech_subs.get(t, set())) == 1),
            4,
        )
        rows.append({
            "subcategory":        sub,
            "raw_coverage":       raw,
            "weighted_coverage":  wgt,
            "unique_coverage":    uniq,
            "techniques_covered": ";".join(sorted(techs)),
        })

    df = pd.DataFrame(rows).merge(
        csf[["subcategory", "function_code", "function",
             "category_code", "category"]],
        on="subcategory",
    )
    # nice ordering
    return df[[
        "function_code", "function", "category_code", "category", "subcategory",
        "raw_coverage", "weighted_coverage", "unique_coverage",
        "techniques_covered",
    ]]


def add_greedy_marginal(coverage: pd.DataFrame,
                        sme: pd.DataFrame,
                        weights: pd.DataFrame) -> pd.DataFrame:
    """Compute greedy_rank and marginal_at_rank via set-cover heuristic.

    Sorts Subcategories in descending order of weighted_coverage, iterates,
    and records how much *not-yet-covered* weight each one adds when picked.

    Subcategories that address zero SME-relevant techniques get greedy_rank = NA
    and marginal_at_rank = 0.
    """
    tech_weight: Dict[str, float] = dict(
        zip(weights["technique_id"], weights["weight"])
    )
    sub_techs: Dict[str, Set[str]] = (
        sme.groupby("subcategory")["technique_id"]
           .apply(set).to_dict()
    )

    # Only rank Subcategories that actually cover something
    ranked = (coverage[coverage["weighted_coverage"] > 0]
              .sort_values("weighted_coverage", ascending=False)
              ["subcategory"].tolist())

    covered: Set[str] = set()
    rank: Dict[str, int]     = {}
    marginal: Dict[str, float] = {}
    for r, sub in enumerate(ranked, start=1):
        techs   = sub_techs.get(sub, set())
        new_t   = techs - covered
        marginal[sub] = round(sum(tech_weight.get(t, 0) for t in new_t), 4)
        rank[sub]     = r
        covered |= techs

    out = coverage.copy()
    out["greedy_rank"]      = out["subcategory"].map(rank).astype("Int64")
    out["marginal_at_rank"] = out["subcategory"].map(marginal).fillna(0.0)
    return out


def residual_threats(sme: pd.DataFrame,
                     weights: pd.DataFrame) -> pd.DataFrame:
    """One row per SME-relevant technique with coverage-counts.

    Highlights techniques weighted highly but covered by few Subcategories.
    The `residual_priority` column combines both: high weight + few coverers
    = high priority to address in the dissertation Discussion.
    """
    covers = (sme.groupby("technique_id")
                 .agg(covering_subs_count=("subcategory", "nunique"),
                      covering_subs=("subcategory",
                                     lambda s: ";".join(sorted(set(s)))))
                 .reset_index())

    out = weights.merge(covers, on="technique_id", how="left")
    out["covering_subs_count"] = out["covering_subs_count"].fillna(0).astype(int)
    out["covering_subs"]       = out["covering_subs"].fillna("")

    # weight * inverse-coverage: unreachable techniques get full weight residual;
    # heavily covered ones get their weight discounted proportionally.
    out["residual_priority"] = (
        out["weight"] / (1 + out["covering_subs_count"])
    ).round(4)

    # sort so most-residual first
    return (out.sort_values(["residual_priority", "weight"],
                            ascending=[False, False])
               .reset_index(drop=True))


def format_report(cov: pd.DataFrame, res: pd.DataFrame) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append("  SCORE (Phase 5) REPORT")
    lines.append("=" * 78)

    n_scored  = int((cov["raw_coverage"] > 0).sum())
    total_wgt = float(cov["weighted_coverage"].sum())
    lines.append(f"  Subcategories with any SME coverage ..... {n_scored:>4} / {len(cov)}")
    lines.append(f"  Total SME weight distributed ............ {total_wgt:>6.2f}")
    lines.append("")

    lines.append("  TOP 20 by GREEDY MARGINAL (the priority list to actually implement)")
    lines.append("  " + "-" * 76)
    lines.append(f"  {'Rank':<5}{'Subcategory':<12}{'Function':<14}{'Marginal':>10}"
                 f"{'Weighted':>10}{'Raw':>6}")
    top20 = cov.sort_values("greedy_rank").head(20)
    for _, r in top20.iterrows():
        lines.append(f"  {int(r['greedy_rank']):<5}{r['subcategory']:<12}"
                     f"{r['function']:<14}{r['marginal_at_rank']:>10.4f}"
                     f"{r['weighted_coverage']:>10.4f}{int(r['raw_coverage']):>6}")
    lines.append("")

    lines.append("  TOP 10 RESIDUAL SME THREATS (weight ÷ (1 + coverers))")
    lines.append("  " + "-" * 76)
    lines.append(f"  {'Technique':<12}{'Name':<40}{'Weight':>8}{'#Covs':>7}"
                 f"{'Resid':>9}")
    for _, r in res.head(10).iterrows():
        nm = (r['name'] or '')[:38]
        lines.append(f"  {r['technique_id']:<12}{nm:<40}"
                     f"{r['weight']:>8.3f}{int(r['covering_subs_count']):>7}"
                     f"{r['residual_priority']:>9.4f}")
    lines.append("")

    # Uncovered techniques call-out
    unreached = res[res["covering_subs_count"] == 0]
    lines.append(f"  Techniques with ZERO Subcategory coverage: {len(unreached)}")
    if len(unreached):
        for _, r in unreached.iterrows():
            lines.append(f"      {r['technique_id']}  weight={r['weight']:.3f}  {r['name']}")
    lines.append("=" * 78)
    return "\n".join(lines)



def main():
    PROCESSED.mkdir(parents=True, exist_ok=True)
    OUTPUTS.mkdir(parents=True, exist_ok=True)

    print("[score] loading intermediate frames ...")
    csf     = ingest.load_csf_subcategories()
    weights = ingest.load_sme_weights()

    if flt.SME_BRIDGE_CSV.exists():
        print(f"[score] loading SME bridge from {flt.SME_BRIDGE_CSV.name}")
        sme = pd.read_csv(flt.SME_BRIDGE_CSV)
    else:
        print("[score] sme_bridge.csv missing - rerun filter phase first")
        raise SystemExit(1)

    print("[score] computing raw / weighted / unique coverage ...")
    coverage = compute_coverage_matrix(sme, csf, weights)

    print("[score] computing greedy marginal ...")
    coverage = add_greedy_marginal(coverage, sme, weights)

    print("[score] computing residual threats ...")
    residual = residual_threats(sme, weights)

    print(f"[score] writing outputs")
    coverage.to_csv(COVERAGE_CSV, index=False)
    residual.to_csv(RESIDUAL_CSV, index=False)
    # Convenience: Top-20 by greedy_rank as its own file
    (coverage.dropna(subset=["greedy_rank"])
             .sort_values("greedy_rank").head(20)
             .to_csv(TOP20_CSV, index=False))

    report = format_report(coverage, residual)
    SCORE_STATS.write_text(report, encoding="utf-8")
    print(report)
    print(f"\n  Wrote: {COVERAGE_CSV}")
    print(f"  Wrote: {RESIDUAL_CSV}")
    print(f"  Wrote: {TOP20_CSV}")


if __name__ == "__main__":
    main()
