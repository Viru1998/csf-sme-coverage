from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List

import pandas as pd

from . import ingest, filter as flt, score, irish_overlay

ROOT      = Path(__file__).resolve().parents[2]
OUTPUTS   = ROOT / "outputs"
FIGURES   = OUTPUTS / "figures"
MD_REPORT = OUTPUTS / "FINDINGS_SUMMARY.md"
MANIFEST  = OUTPUTS / "outputs_manifest.txt"

FIG1 = "figures/fig1_function_tactic_heatmap.png"
FIG2 = "figures/fig2_top20_combined_priority.png"
FIG3 = "figures/fig3_verizon_vs_irish_top10.png"
FIG4 = "figures/fig4_function_urgency_quadrant.png"
FIG5 = "figures/fig5_enisa_corroboration.png"

def _df_to_md(df: pd.DataFrame, cols: List[str], headers: List[str] = None) -> str:
    """Render a subset of a DataFrame as a compact Markdown table."""
    view = df[cols].copy()
    if headers:
        view.columns = headers
    try:
        return view.to_markdown(index=False, floatfmt=".3f")
    except ImportError:  # tabulate not installed
        return view.to_string(index=False)


def _figure_block(title: str, path: str, caption: str) -> str:
    return (f"### {title}\n\n"
            f"![{title}]({path})\n\n"
            f"*{caption}*\n")


def build_findings_summary() -> str:
    coverage  = pd.read_csv(score.COVERAGE_CSV)
    residual  = pd.read_csv(score.RESIDUAL_CSV)
    combined  = pd.read_csv(irish_overlay.COMBINED_PRIORITY)
    urgency   = pd.read_csv(irish_overlay.FUNCTION_URGENCY)
    irish_gap = pd.read_csv(irish_overlay.IRISH_GAP_RANKING)
    ncsc_ie   = pd.read_csv(irish_overlay.NCSC_IE_ALIGNMENT)
    enisa     = pd.read_csv(irish_overlay.ENISA_CORROBORATION)
    weights   = ingest.load_sme_weights()

    n_subs_scored     = int((coverage["raw_coverage"] > 0).sum())
    n_subs_total      = len(coverage)
    total_dist_weight = float(coverage["weighted_coverage"].sum())
    total_sme_weight  = float(weights["weight"].sum())
    n_sme_techs       = len(weights)
    enisa_covered     = float(enisa["verizon_weight_sum"].sum())
    enisa_pct         = 100 * enisa_covered / max(total_sme_weight, 1e-9)
    residual_zero     = int((residual["covering_subs_count"] == 0).sum())

    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines = []

    # ----- Header --------------------------------------------------------
    lines += [
        "# CSF 2.0 SME Threat-Informed Effectiveness — Findings Report",
        "",
        f"**Author:** Viraj Ananda Gawde  \\  Student ID 24135909  ",
        f"**Programme:** MSc Cybersecurity, National College of Ireland  ",
        f"**Generated:** {now}  ",
        f"**Pipeline version:** 0.1.0  ",
        "",
        "This report is generated automatically by `report.py`. Every "
        "table below is derived from the CSV files in this folder; every "
        "figure is a PNG in `figures/`. Rerun with `python -m csf_sme_coverage.report`.",
        "",
        "---",
        "",
    ]

    # ----- Executive summary --------------------------------------------
    lines += [
        "## Executive Summary",
        "",
        f"* CSF 2.0 Subcategories analysed: **{n_subs_total}** "
          f"(of which {n_subs_scored} have any Verizon-derived SME threat coverage)",
        f"* SME-relevant ATT&CK techniques weighted (Verizon DBIR 2026, n=7,152 SMB breaches): "
          f"**{n_sme_techs}**",
        f"* Total distributed SME weight across CSF Subcategories: **{total_dist_weight:.2f}**",
        f"* ATT&CK techniques with zero CSF coverage (residual): **{residual_zero}**",
        f"* ENISA 2024 EU prime-threat corroboration: "
          f"**{enisa_pct:.1f}%** of total SME weight sits under ENISA prime threats",
        "",
        "---",
        "",
    ]

    # ----- Section 1: headline priority list ----------------------------
    lines += [
        "## 1. Top-20 Combined Double-Witness Priority",
        "",
        "Combines Verizon-derived SME threat coverage with MTU/NCSC 2025 "
        "Irish SME adoption gap: high combined score = high threat weight "
        "AND large Irish adoption gap.",
        "",
        _df_to_md(combined.head(20),
                  ["subcategory", "function", "weighted_coverage",
                   "irish_gap_pct", "combined_score"],
                  ["Subcat", "Function", "Weight", "Gap%", "Combined"]),
        "",
        _figure_block(
            "Figure 4.1 — Top-20 Priority",
            FIG2,
            "CSF 2.0 Subcategories ranked by combined double-witness priority. "
            "Colour indicates CSF Function; label shows Irish adoption gap.",
        ),
        "---",
        "",
    ]

    # ----- Section 2: global vs Irish comparison ------------------------
    lines += [
        "## 2. Global (Verizon SMB) vs Irish (MTU/NCSC 2025) Comparison",
        "",
        "### 2.1 Verizon-based Top-10 by weighted coverage",
        "",
        _df_to_md(
            coverage.dropna(subset=["greedy_rank"]).sort_values("greedy_rank").head(10),
            ["subcategory", "function", "weighted_coverage", "raw_coverage"],
            ["Subcat", "Function", "Weight", "Raw #"],
        ),
        "",
        "### 2.2 MTU/NCSC 2025 Top-10 Irish SME Adoption Gaps",
        "",
        _df_to_md(
            irish_gap,
            ["irish_rank", "weakness", "irish_gap_pct", "csf_subcategories"],
            ["#", "Weakness", "Gap%", "CSF Subcategories"],
        ),
        "",
        _figure_block(
            "Figure 4.2 — Global vs Irish Top-10",
            FIG3,
            "Side-by-side comparison. Left panel: Verizon-derived Top-10 "
            "CSF Subcategories by threat coverage. Right panel: Top-10 "
            "quantified weaknesses among 894 Irish SMEs.",
        ),
        "---",
        "",
    ]

    # ----- Section 3: per-Function urgency ------------------------------
    lines += [
        "## 3. Per-CSF-Function Urgency Matrix",
        "",
        "Urgency verdict combines Verizon weight sum with MTU/NCSC 2025 mean Irish gap.",
        "",
        _df_to_md(
            urgency,
            ["function", "verizon_weight_sum", "irish_avg_gap",
             "irish_max_gap", "urgency"],
            ["Function", "Verizon Weight", "Irish Avg Gap%",
             "Irish Max Gap%", "Verdict"],
        ),
        "",
        _figure_block(
            "Figure 4.3 — Function Urgency Quadrant",
            FIG4,
            "Each CSF Function positioned on (Verizon threat weight, Irish "
            "adoption gap) axes. Upper-right quadrant = URGENT. GOVERN and "
            "RESPOND appear as LOW PRIORITY under threat-informed coverage "
            "despite large Irish gaps - see Discussion (Chapter 5) for the "
            "methodological implication.",
        ),
        "---",
        "",
    ]

    # ----- Section 4: NCSC IE alignment --------------------------------
    lines += [
        "## 4. NCSC Ireland Guidance Alignment",
        "",
        "NCSC Ireland's six prescriptive core measures, cross-referenced with "
        "the Verizon-derived weighted coverage of the CSF Subcategories that "
        "each measure operationalises.",
        "",
        _df_to_md(
            ncsc_ie,
            ["ncsc_ie_measure_no", "title", "csf_subcategories",
             "verizon_weighted_coverage_sum"],
            ["#", "NCSC IE Measure", "CSF Subcategories", "Verizon Weight"],
        ),
        "",
        "---",
        "",
    ]

    # ----- Section 5: ENISA corroboration -------------------------------
    lines += [
        "## 5. ENISA 2024 European-Lens Corroboration",
        "",
        f"Four of the seven ENISA 2024 prime EU threats are directly covered "
        f"by our Verizon-derived weighted technique set, together accounting "
        f"for **{enisa_pct:.1f}%** of the total distributed SME weight.",
        "",
        _df_to_md(
            enisa,
            ["enisa_rank", "enisa_threat", "in_verizon_weights",
             "verizon_weight_sum", "covered_techniques"],
            ["#", "ENISA Prime Threat", "In Set", "Weight", "Techniques"],
        ),
        "",
        _figure_block(
            "Figure 4.4 — ENISA Corroboration",
            FIG5,
            "Weight of Verizon-derived SME techniques sitting under each "
            "ENISA 2024 prime EU threat category. Blue: covered; grey: not "
            "in current SME weight set.",
        ),
        "---",
        "",
    ]

    # ----- Section 6: residual threats ---------------------------------
    lines += [
        "## 6. Residual SME-Relevant Threats",
        "",
        "SME-relevant techniques ranked by residual priority "
        "(weight ÷ (1 + number of covering Subcategories)). "
        "High values = high SMB threat weight AND few CSF controls covering them.",
        "",
        _df_to_md(
            residual.head(10),
            ["technique_id", "name", "weight",
             "covering_subs_count", "residual_priority"],
            ["ATT&CK ID", "Name", "Weight", "#Covers", "Residual"],
        ),
        "",
        "---",
        "",
    ]

    # ----- Section 7: coverage heatmap ----------------------------------
    lines += [
        "## 7. CSF Function × ATT&CK Tactic Coverage Heatmap",
        "",
        _figure_block(
            "Figure 4.5 — Function × Tactic Heatmap",
            FIG1,
            "Sum of weighted SME coverage across the six CSF Functions and "
            "the fourteen ATT&CK Enterprise Tactics (kill-chain order). "
            "Darker cells = higher aggregate weighted coverage.",
        ),
        "---",
        "",
    ]

    # ----- Data provenance ---------------------------------------------
    lines += [
        "## Data Provenance",
        "",
        "| Layer | Source | Sample / Version |",
        "|---|---|---|",
        "| Framework backbone | NIST CSF 2.0 (CSWP 29) | 106 active Subcategories |",
        "| Bridge leg 1 | NIST CSF v2.0 → SP 800-53 Rev 5 Crosswalk (OLIR #186, draft) | 740 mapping rows |",
        "| Bridge leg 2 | Center for Threat-Informed Defense 800-53 → ATT&CK v16.1 | 5,264 mapping rows |",
        "| Threat catalogue | MITRE ATT&CK Enterprise v16.1 | 799 techniques |",
        "| Primary SME weights | Verizon DBIR 2026, Small Business section (pp.97-98) | n = 7,152 SMB breaches |",
        "| Secondary SME weights | Verizon DBIR 2026, System Intrusion pattern (pp.40-41) | n = 12,006 breaches |",
        "| Irish empirical context | MTU + NCSC (2025) State of the Sector | n = 894 Irish SMEs |",
        "| Irish regulatory anchor | NCSC Ireland (2025) SME Cyber Security Guidance | 6 core measures |",
        "| European corroboration | ENISA (2024) Threat Landscape | 7 prime EU threats |",
        "",
        "All data sources are version-pinned in `data/raw/`. Pipeline reproducible "
        "via `make all` or `python -m csf_sme_coverage.cli`.",
        "",
    ]

    return "\n".join(lines)


def build_manifest() -> str:
    lines = ["# Outputs manifest", "# Generated automatically by report.py", ""]
    lines.append(f"# {'file':<50} {'size':>12}  {'modified':<19}")
    lines.append("# " + "-" * 90)

    for p in sorted(OUTPUTS.rglob("*")):
        if p.is_dir() or p.name.startswith("."):
            continue
        rel  = p.relative_to(OUTPUTS)
        size = p.stat().st_size
        mt   = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        # human-readable size
        if size < 1024:
            sz = f"{size} B"
        elif size < 1024 * 1024:
            sz = f"{size/1024:.1f} KB"
        else:
            sz = f"{size/1024/1024:.2f} MB"
        lines.append(f"  {str(rel):<50} {sz:>12}  {mt}")

    return "\n".join(lines)


def main():
    OUTPUTS.mkdir(parents=True, exist_ok=True)

    # Check prerequisites
    required = [score.COVERAGE_CSV, score.RESIDUAL_CSV,
                irish_overlay.COMBINED_PRIORITY, irish_overlay.FUNCTION_URGENCY,
                irish_overlay.IRISH_GAP_RANKING, irish_overlay.NCSC_IE_ALIGNMENT,
                irish_overlay.ENISA_CORROBORATION]
    missing = [p for p in required if not p.exists()]
    if missing:
        print("[report] required outputs missing:")
        for m in missing:
            print(f"           {m}")
        print("[report] run the earlier phases first (score, irish_overlay).")
        raise SystemExit(1)

    print("[report] composing findings summary ...")
    md = build_findings_summary()
    MD_REPORT.write_text(md, encoding="utf-8")
    print(f"[report]   wrote {MD_REPORT}")

    print("[report] composing outputs manifest ...")
    manifest = build_manifest()
    MANIFEST.write_text(manifest, encoding="utf-8")
    print(f"[report]   wrote {MANIFEST}")

    print()
    print(f"  Findings summary  : {MD_REPORT}")
    print(f"  Outputs manifest  : {MANIFEST}")
    print()
    print("  Open FINDINGS_SUMMARY.md in a Markdown viewer (VS Code preview, "
          "GitHub, or Typora) to see the report rendered.")


if __name__ == "__main__":
    main()
