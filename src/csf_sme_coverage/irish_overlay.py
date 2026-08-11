"""
irish_overlay.py - Irish-context overlay on the Verizon-derived global analysis.

Answers the question examiners will ask: "how does this apply to Irish SMEs?"

Two data blocks feed this module:

  * The Verizon-based coverage_matrix.csv from score.py (global SMB baseline).
  * The hand-curated data/raw/irish_context.yml, which carries:
      - MTU/NCSC 2025 top-10 Irish gap statistics (n=894 SMEs)
      - MTU/NCSC 2025 per-CSF-Function readiness percentages
      - NCSC Ireland 2025 prescriptive 6 core measures for SMEs

Four output tables are produced (all written to outputs/):

  irish_gap_ranking.csv          Irish top-10 gaps side-by-side with our
                                 Verizon-based scoring for the same
                                 Subcategories - i.e. "these are the actual
                                 gaps and here is how much SMB threat weight
                                 each closes"

  ncsc_ie_alignment.csv          NCSC Ireland's 6 core measures mapped to
                                 CSF Subcategories, cross-referenced with
                                 our Verizon-based scoring - i.e. does the
                                 threat-informed ranking agree with what
                                 NCSC IE prescribes?

  combined_priority.csv          Combined ranking = weighted_coverage x
                                 Irish gap magnitude - the "double-witness"
                                 priority: high threat weight AND large
                                 Irish gap. Rank-1 here is the strongest
                                 recommendation you can make in Chapter 5.

  function_urgency.csv           Per-CSF-Function matrix showing threat-
                                 relevance (from Verizon) alongside Irish
                                 gap severity (from MTU/NCSC) - highlights
                                 which Functions need URGENT vs LOW attention.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import pandas as pd
import yaml

from . import ingest, score

ROOT      = Path(__file__).resolve().parents[2]
RAW       = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
OUTPUTS   = ROOT / "outputs"

IRISH_YML             = RAW / "irish_context.yml"
IRISH_GAP_RANKING     = OUTPUTS / "irish_gap_ranking.csv"
NCSC_IE_ALIGNMENT     = OUTPUTS / "ncsc_ie_alignment.csv"
COMBINED_PRIORITY     = OUTPUTS / "combined_priority.csv"
FUNCTION_URGENCY      = OUTPUTS / "function_urgency.csv"
ENISA_CORROBORATION   = OUTPUTS / "enisa_corroboration.csv"
IRISH_STATS           = PROCESSED / "irish_overlay_stats.txt"


def load_irish_context(path: Path = IRISH_YML) -> dict:
    """Return the parsed YAML with metadata + three data blocks."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def irish_gap_ranking(irish: dict,
                      coverage: pd.DataFrame) -> pd.DataFrame:
    """One row per Irish top-10 weakness, joined with Verizon coverage stats
    for the Subcategories the weakness maps to.
    """
    rows = []
    cov_lookup = coverage.set_index("subcategory")

    for entry in irish["top_10_gaps"]:
        subs = entry["csf_subcategories"]
        # Roll up Verizon-based coverage across the mapped Subcategories
        matches = coverage[coverage["subcategory"].isin(subs)]
        rows.append({
            "irish_rank":         entry["rank"],
            "weakness":           entry["weakness"],
            "irish_gap_pct":      entry["gap_pct"],
            "irish_adoption_pct": entry["adoption_pct"],
            "csf_subcategories":  ";".join(subs),
            "verizon_weighted_coverage_sum":  round(matches["weighted_coverage"].sum(), 4),
            "verizon_raw_coverage_max":       int(matches["raw_coverage"].max() or 0),
            "verizon_marginal_at_rank_max":   round(matches["marginal_at_rank"].max() or 0, 4),
            "verizon_best_greedy_rank":       int(matches["greedy_rank"].min() or 0) if matches["greedy_rank"].notna().any() else 0,
            "source":             entry["source"],
        })

    return (pd.DataFrame(rows)
              .sort_values("irish_rank")
              .reset_index(drop=True))



def ncsc_ie_alignment(irish: dict,
                      coverage: pd.DataFrame) -> pd.DataFrame:
    """One row per NCSC Ireland prescriptive measure with the CSF Subcategories
    that operationalise it and their Verizon-based scoring.
    """
    rows = []
    for m in irish["ncsc_ie_measures"]:
        subs = m["csf_subcategories"]
        matches = coverage[coverage["subcategory"].isin(subs)]
        rows.append({
            "ncsc_ie_measure_no":  m["number"],
            "title":               m["title"],
            "description":         m["description"],
            "csf_subcategories":   ";".join(subs),
            "verizon_weighted_coverage_sum":  round(matches["weighted_coverage"].sum(), 4),
            "verizon_raw_coverage_max":       int(matches["raw_coverage"].max() or 0),
            "verizon_best_greedy_rank":       int(matches["greedy_rank"].min() or 0) if matches["greedy_rank"].notna().any() else 0,
            "source":              m["source"],
        })
    return pd.DataFrame(rows)


def combined_priority(irish: dict,
                      coverage: pd.DataFrame) -> pd.DataFrame:
    """For each CSF Subcategory: combined score = verizon_weighted_coverage
    times the largest Irish gap that maps to it (divided by 100 to normalise).

    Rank-1 is the Subcategory with both the highest threat weight AND the
    largest Irish adoption gap - i.e. "we know this closes threat coverage
    AND we know Irish SMEs don't have it".
    """
    # Build a lookup: Subcategory -> max Irish gap % that maps to it
    sub_to_gap: Dict[str, float] = {}
    sub_to_source: Dict[str, str] = {}
    for entry in irish["top_10_gaps"]:
        for s in entry["csf_subcategories"]:
            if entry["gap_pct"] > sub_to_gap.get(s, 0):
                sub_to_gap[s] = entry["gap_pct"]
                sub_to_source[s] = f"MTU/NCSC top-10 #{entry['rank']}: {entry['weakness']}"
    # Also pick up the per-Function block for Subcategories not in top-10
    for fn, stats in irish["function_gaps"].items():
        for st in stats:
            for s in st["csf_subcategories"]:
                if st["gap_pct"] > sub_to_gap.get(s, 0):
                    sub_to_gap[s] = st["gap_pct"]
                    sub_to_source[s] = f"MTU/NCSC {fn}: {st['stat']}"

    out = coverage.copy()
    out["irish_gap_pct"]     = out["subcategory"].map(sub_to_gap).fillna(0).astype(int)
    out["irish_gap_source"]  = out["subcategory"].map(sub_to_source).fillna("")
    out["combined_score"]    = (
        out["weighted_coverage"] * out["irish_gap_pct"] / 100
    ).round(4)

    return (out.sort_values("combined_score", ascending=False)
              .reset_index(drop=True)
              [["function_code", "function", "subcategory",
                "weighted_coverage", "irish_gap_pct", "combined_score",
                "greedy_rank", "marginal_at_rank", "raw_coverage",
                "irish_gap_source"]])


def function_urgency(irish: dict,
                     coverage: pd.DataFrame) -> pd.DataFrame:
    """Per-CSF-Function: total Verizon weighted coverage available AND the mean
    Irish gap across mapped Subcategories, from the MTU/NCSC per-function block.

    Quadrant reading:
      * High weight AND high gap = URGENT priority
      * High weight, low gap     = "Ireland is already doing this reasonably"
      * Low weight, high gap     = "large Irish gap but low threat leverage"
      * Low weight, low gap      = "low priority for now"
    """
    # Verizon side: sum weighted coverage per Function
    fn_verizon = (coverage.groupby(["function_code", "function"])
                          ["weighted_coverage"].sum().reset_index()
                          .rename(columns={"weighted_coverage": "verizon_weight_sum"}))

    # Irish side: mean gap across the per-Function block
    rows = []
    for fn_name, stats in irish["function_gaps"].items():
        avg_gap  = sum(s["gap_pct"] for s in stats) / max(len(stats), 1)
        max_gap  = max(s["gap_pct"] for s in stats) if stats else 0
        rows.append({
            "function":         fn_name.upper(),
            "irish_avg_gap":    round(avg_gap, 1),
            "irish_max_gap":    max_gap,
            "n_stats":          len(stats),
        })
    fn_irish = pd.DataFrame(rows)

    out = fn_verizon.merge(fn_irish, on="function", how="outer")

    # Urgency quadrant label (uses median as split for both metrics)
    med_v = out["verizon_weight_sum"].median()
    med_i = out["irish_avg_gap"].median()

    def _quadrant(r):
        v_hi = (r["verizon_weight_sum"] or 0) >= med_v
        i_hi = (r["irish_avg_gap"] or 0) >= med_i
        if v_hi and i_hi:
            return "URGENT"
        if v_hi and not i_hi:
            return "IRELAND OK"
        if not v_hi and i_hi:
            return "GAP BUT LOW THREAT LEVERAGE"
        return "LOW PRIORITY"

    out["urgency"] = out.apply(_quadrant, axis=1)
    return out.sort_values("verizon_weight_sum", ascending=False).reset_index(drop=True)



def enisa_corroboration(irish: dict,
                        weights: pd.DataFrame) -> pd.DataFrame:
    """For each ENISA prime threat: whether we cover it in our Verizon-derived
    weighted technique set, and if so how much weight sits under it.
    """
    weight_lookup = dict(zip(weights["technique_id"], weights["weight"]))
    rows = []
    for e in irish["enisa_corroboration"]["prime_threats"]:
        mapped = e.get("mapped_verizon_techniques") or []
        covered = [t for t in mapped if t in weight_lookup]
        rows.append({
            "enisa_rank":                 e["rank"],
            "enisa_threat":               e["threat"],
            "in_verizon_weights":         "YES" if covered else "NO",
            "mapped_techniques":          ";".join(mapped),
            "covered_techniques":         ";".join(covered),
            "verizon_weight_sum":         round(sum(weight_lookup.get(t, 0)
                                                    for t in covered), 4),
            "note":                       e.get("note", ""),
            "source":                     e["source"],
        })
    return pd.DataFrame(rows)



def format_report(gap: pd.DataFrame,
                  ncsc_ie: pd.DataFrame,
                  combined: pd.DataFrame,
                  urgency: pd.DataFrame,
                  enisa: pd.DataFrame) -> str:
    lines = []
    lines.append("=" * 88)
    lines.append("  IRISH OVERLAY (Phase 5.5) REPORT")
    lines.append("=" * 88)
    lines.append("")

    lines.append("  1. IRISH TOP-10 GAPS  vs  VERIZON-BASED COVERAGE")
    lines.append("  " + "-" * 86)
    lines.append(f"  {'#':<3}{'Weakness':<40}{'Gap%':>5}{'W-Cov':>8}{'BestRank':>10}")
    for _, r in gap.iterrows():
        lines.append(f"  {r['irish_rank']:<3}{r['weakness'][:38]:<40}"
                     f"{r['irish_gap_pct']:>5}"
                     f"{r['verizon_weighted_coverage_sum']:>8.3f}"
                     f"{r['verizon_best_greedy_rank']:>10}")
    lines.append("")

    lines.append("  2. NCSC IRELAND 6 CORE MEASURES  vs  VERIZON-BASED COVERAGE")
    lines.append("  " + "-" * 86)
    lines.append(f"  {'#':<3}{'Measure':<38}{'W-Cov':>10}{'BestRank':>10}")
    for _, r in ncsc_ie.iterrows():
        lines.append(f"  {r['ncsc_ie_measure_no']:<3}{r['title'][:36]:<38}"
                     f"{r['verizon_weighted_coverage_sum']:>10.3f}"
                     f"{r['verizon_best_greedy_rank']:>10}")
    lines.append("")

    lines.append("  3. COMBINED DOUBLE-WITNESS PRIORITY  (top 15 by threat weight x Irish gap)")
    lines.append("  " + "-" * 86)
    lines.append(f"  {'Rank':<5}{'Subcat':<10}{'Function':<12}{'W-Cov':>8}"
                 f"{'Gap%':>6}{'Combined':>10}")
    for i, r in combined.head(15).iterrows():
        lines.append(f"  {i+1:<5}{r['subcategory']:<10}{r['function']:<12}"
                     f"{r['weighted_coverage']:>8.3f}{r['irish_gap_pct']:>6}"
                     f"{r['combined_score']:>10.4f}")
    lines.append("")

    lines.append("  4. PER-FUNCTION URGENCY MATRIX")
    lines.append("  " + "-" * 86)
    lines.append(f"  {'Function':<14}{'VerizonW':>10}{'IrishGap%':>10}"
                 f"    {'Verdict':<32}")
    for _, r in urgency.iterrows():
        v = r["verizon_weight_sum"] if pd.notna(r["verizon_weight_sum"]) else 0
        g = r["irish_avg_gap"]      if pd.notna(r["irish_avg_gap"])      else 0
        lines.append(f"  {r['function']:<14}{v:>10.2f}{g:>10.1f}"
                     f"    {r['urgency']:<32}")
    lines.append("")

    lines.append("  5. ENISA 2024 EU-LENS CORROBORATION")
    lines.append("  " + "-" * 86)
    lines.append(f"  {'#':<3}{'ENISA prime threat':<38}{'InSet':>6}"
                 f"{'WgtSum':>10}    {'Techniques':<20}")
    for _, r in enisa.iterrows():
        lines.append(f"  {r['enisa_rank']:<3}{r['enisa_threat'][:36]:<38}"
                     f"{r['in_verizon_weights']:>6}"
                     f"{r['verizon_weight_sum']:>10.3f}"
                     f"    {r['covered_techniques'][:60]}")
    covered_sum = enisa["verizon_weight_sum"].sum()
    total_wgt   = 2.77  # sum of all Verizon-derived weights
    pct = 100 * covered_sum / total_wgt
    lines.append(f"  " + " " * 47 + f"Total: {covered_sum:.3f} = {pct:.1f}% of SME weight")
    lines.append("=" * 88)
    return "\n".join(lines)


def main():
    OUTPUTS.mkdir(parents=True, exist_ok=True)
    PROCESSED.mkdir(parents=True, exist_ok=True)

    print("[irish] loading Irish context YAML ...")
    irish = load_irish_context()

    if not score.COVERAGE_CSV.exists():
        print("[irish] coverage_matrix.csv missing - rerun score phase first")
        raise SystemExit(1)
    print(f"[irish] loading Verizon coverage from {score.COVERAGE_CSV.name}")
    coverage = pd.read_csv(score.COVERAGE_CSV)

    print("[irish] loading SME weights (for ENISA corroboration lookup) ...")
    weights = ingest.load_sme_weights()

    print("[irish] computing overlays ...")
    gap      = irish_gap_ranking(irish, coverage)
    ncsc_ie  = ncsc_ie_alignment(irish, coverage)
    combined = combined_priority(irish, coverage)
    urgency  = function_urgency(irish, coverage)
    enisa    = enisa_corroboration(irish, weights)

    print(f"[irish] writing outputs")
    gap.to_csv(IRISH_GAP_RANKING, index=False)
    ncsc_ie.to_csv(NCSC_IE_ALIGNMENT, index=False)
    combined.to_csv(COMBINED_PRIORITY, index=False)
    urgency.to_csv(FUNCTION_URGENCY, index=False)
    enisa.to_csv(ENISA_CORROBORATION, index=False)

    report = format_report(gap, ncsc_ie, combined, urgency, enisa)
    IRISH_STATS.write_text(report, encoding="utf-8")
    print(report)
    print()
    print(f"  Wrote: {IRISH_GAP_RANKING}")
    print(f"  Wrote: {NCSC_IE_ALIGNMENT}")
    print(f"  Wrote: {COMBINED_PRIORITY}")
    print(f"  Wrote: {FUNCTION_URGENCY}")
    print(f"  Wrote: {ENISA_CORROBORATION}")


if __name__ == "__main__":
    main()
