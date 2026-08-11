from __future__ import annotations

from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd
import seaborn as sns

from . import ingest, filter as flt, score, irish_overlay


ROOT      = Path(__file__).resolve().parents[2]
OUTPUTS   = ROOT / "outputs"
FIGURES   = OUTPUTS / "figures"

FIG1 = FIGURES / "fig1_function_tactic_heatmap.png"
FIG2 = FIGURES / "fig2_top20_combined_priority.png"
FIG3 = FIGURES / "fig3_verizon_vs_irish_top10.png"
FIG4 = FIGURES / "fig4_function_urgency_quadrant.png"
FIG5 = FIGURES / "fig5_enisa_corroboration.png"

CSF_FUNCTIONS = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
FUNCTION_COLOURS = {
    "GOVERN":   "#1f4e79",
    "IDENTIFY": "#2e75b6",
    "PROTECT":  "#5B9BD5",
    "DETECT":   "#70AD47",
    "RESPOND":  "#ED7D31",
    "RECOVER":  "#C00000",
}
ATTACK_TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

sns.set_style("whitegrid")
plt.rcParams.update({
    "font.family":       "DejaVu Sans",
    "axes.titlesize":    13,
    "axes.labelsize":    11,
    "xtick.labelsize":   9,
    "ytick.labelsize":   9,
    "legend.fontsize":   9,
    "figure.dpi":        160,
    "savefig.dpi":       300,
    "savefig.bbox":      "tight",
    "savefig.pad_inches": 0.30,
})


def fig1_function_tactic_heatmap(sme: pd.DataFrame,
                                 weights: pd.DataFrame,
                                 out: Path = FIG1) -> Path:
    tw = dict(zip(weights["technique_id"], weights["weight"]))
    sme = sme.copy()
    sme["weight"] = sme["technique_id"].map(tw).fillna(0)

    rows = []
    for _, r in sme.iterrows():
        for tac in str(r["tactic"]).split(","):
            tac = tac.strip()
            if not tac:
                continue
            rows.append({"function": r["function"].upper(),
                         "tactic": tac,
                         "weight": r["weight"]})
    long = pd.DataFrame(rows)

    matrix = (long.groupby(["function", "tactic"])["weight"]
                  .sum().unstack(fill_value=0.0))
    matrix = matrix.reindex(index=CSF_FUNCTIONS, columns=ATTACK_TACTICS,
                            fill_value=0.0)

    # Wider figure, rotated x-labels
    fig, ax = plt.subplots(figsize=(17, 5.5))
    sns.heatmap(matrix, cmap="YlOrRd", annot=True, fmt=".2f",
                linewidths=0.8, linecolor="white",
                cbar_kws={"label": "Sum of weighted coverage", "shrink": 0.75},
                ax=ax,
                annot_kws={"fontsize": 9})
    ax.set_title("CSF 2.0 Function × MITRE ATT&CK Tactic\n"
                 "Weighted Coverage of SME-Relevant Techniques (Verizon-derived)",
                 pad=18)
    ax.set_xlabel("MITRE ATT&CK Tactic (kill-chain order)", labelpad=12)
    ax.set_ylabel("CSF 2.0 Function", labelpad=10)
    # Replace hyphens with spaces, rotate for legibility
    labels = [t.replace("-", " ").title() for t in matrix.columns]
    ax.set_xticklabels(labels, rotation=35, ha="right")
    ax.set_yticklabels(matrix.index, rotation=0)
    plt.savefig(out)
    plt.close(fig)
    return out


def fig2_top20_combined_priority(combined: pd.DataFrame,
                                 out: Path = FIG2) -> Path:
    top20 = combined.head(20).copy().iloc[::-1]  # reverse for barh
    colours = [FUNCTION_COLOURS.get(f, "#888888")
               for f in top20["function"].str.upper()]

    # Compose y-label as "PR.IR-01  (gap 76%)" so the % lives IN the label, not overlapping bars
    top20["ylabel"] = (top20["subcategory"] + "   (gap "
                       + top20["irish_gap_pct"].astype(int).astype(str) + "%)")

    fig, ax = plt.subplots(figsize=(13, 11))
    bars = ax.barh(top20["ylabel"], top20["combined_score"], color=colours,
                   edgecolor="black", linewidth=0.6, height=0.75)

    # Value label at end of each bar
    max_val = top20["combined_score"].max()
    for bar in bars:
        w = bar.get_width()
        ax.text(w + max_val * 0.005,
                bar.get_y() + bar.get_height() / 2,
                f"{w:.2f}", va="center", fontsize=9, color="#333")

    ax.set_xlim(0, max_val * 1.15)
    ax.set_xlabel("Combined double-witness priority\n"
                  "(Verizon-derived weighted coverage × Irish adoption gap %)",
                  labelpad=12)
    ax.set_ylabel("CSF 2.0 Subcategory  (Irish adoption gap)", labelpad=10)
    ax.set_title("Top 20 CSF 2.0 Subcategories for Irish SMEs\n"
                 "Verizon-derived threat coverage × MTU/NCSC 2025 adoption gap",
                 pad=18)

    legend = [mpatches.Patch(color=c, label=fn.title())
              for fn, c in FUNCTION_COLOURS.items()]
    ax.legend(handles=legend, loc="lower right", title="CSF Function",
              frameon=True, framealpha=0.95)

    plt.savefig(out)
    plt.close(fig)
    return out


def fig3_verizon_vs_irish_top10(coverage: pd.DataFrame,
                                irish_gap_rank: pd.DataFrame,
                                out: Path = FIG3) -> Path:
    verizon_top10 = (coverage.dropna(subset=["greedy_rank"])
                             .sort_values("greedy_rank").head(10)).iloc[::-1]
    irish10 = irish_gap_rank.copy().iloc[::-1]
    # Aggressively truncate long weakness names
    irish10["short"] = irish10["weakness"].str.slice(0, 30)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7),
                                    gridspec_kw={"wspace": 0.55})

    # Left: Verizon
    colours1 = [FUNCTION_COLOURS.get(f.upper(), "#888888")
                for f in verizon_top10["function"]]
    bars1 = ax1.barh(verizon_top10["subcategory"], verizon_top10["weighted_coverage"],
                     color=colours1, edgecolor="black", linewidth=0.6, height=0.7)
    for bar in bars1:
        w = bar.get_width()
        ax1.text(w + 0.02, bar.get_y() + bar.get_height() / 2,
                 f"{w:.2f}", va="center", fontsize=8, color="#333")
    ax1.set_title("Verizon-derived Top-10 CSF Subcategories\n"
                  "(weighted coverage of SME-relevant ATT&CK techniques)",
                  pad=14)
    ax1.set_xlabel("Weighted coverage", labelpad=8)
    ax1.set_ylabel("CSF 2.0 Subcategory", labelpad=8)

    # Right: Irish
    bars2 = ax2.barh(irish10["short"], irish10["irish_gap_pct"],
                     color="#B34A44", edgecolor="black", linewidth=0.6,
                     height=0.7)
    for bar in bars2:
        w = bar.get_width()
        ax2.text(w + 1.0, bar.get_y() + bar.get_height() / 2,
                 f"{int(w)}%", va="center", fontsize=8, color="#333")
    ax2.set_title("MTU / NCSC 2025 Top-10 Irish SME Weaknesses\n"
                  "(n = 894 SMEs; % of SMEs LACKING each control)",
                  pad=14)
    ax2.set_xlabel("Irish SME adoption gap (%)", labelpad=8)
    ax2.set_xlim(0, 100)

    # Legend for CSF Functions
    legend = [mpatches.Patch(color=c, label=fn.title())
              for fn, c in FUNCTION_COLOURS.items()]
    ax1.legend(handles=legend, loc="lower right", title="CSF Function",
               fontsize=8, frameon=True)

    fig.suptitle("Global (Verizon SMB) vs Irish (MTU / NCSC 2025) — Top-10 Comparison",
                 fontsize=14, y=1.03)
    plt.savefig(out)
    plt.close(fig)
    return out


def fig4_function_urgency_quadrant(urgency: pd.DataFrame,
                                   out: Path = FIG4) -> Path:
    df = urgency.copy().fillna(0)

    # Manual per-function annotation offsets to avoid overlap
    # Format: (dx, dy, ha) in points from the marker
    offsets = {
        "PROTECT":  (14,  6, "left"),
        "IDENTIFY": (14, -6, "left"),
        "DETECT":   (14,  0, "left"),
        "GOVERN":   (14, 12, "left"),   # push above Recover
        "RECOVER":  (14, -18, "left"),  # push below Govern
        "RESPOND":  (14,  0, "left"),
    }

    fig, ax = plt.subplots(figsize=(12, 8.5))

    # Faint quadrant background shading using medians
    v_med = df["verizon_weight_sum"].median()
    g_med = df["irish_avg_gap"].median()
    xmax  = df["verizon_weight_sum"].max() * 1.15
    ymax  = 100

    ax.axhspan(g_med, ymax, v_med, xmax, facecolor="#FFE4E1", alpha=0.35, zorder=0)
    ax.axhspan(g_med, ymax, 0,     v_med, facecolor="#FFF8DC", alpha=0.35, zorder=0)
    ax.axhspan(0,     g_med, v_med, xmax, facecolor="#E1F5E1", alpha=0.35, zorder=0)
    ax.axhspan(0,     g_med, 0,     v_med, facecolor="#F0F0F0", alpha=0.30, zorder=0)

    # Quadrant labels in corners
    ax.text(xmax * 0.98, 98, "URGENT",
            ha="right", va="top", fontsize=11, fontweight="bold",
            color="#B34A44", alpha=0.65)
    ax.text(v_med * 0.05, 98, "GAP BUT LOW\nTHREAT LEVERAGE",
            ha="left", va="top", fontsize=10, fontweight="bold",
            color="#B58900", alpha=0.65)
    ax.text(xmax * 0.98, 2, "IRELAND OK\n(low gap, high threat)",
            ha="right", va="bottom", fontsize=10, fontweight="bold",
            color="#458B00", alpha=0.65)
    ax.text(v_med * 0.05, 2, "LOW PRIORITY",
            ha="left", va="bottom", fontsize=10, fontweight="bold",
            color="#555555", alpha=0.65)

    ax.axvline(v_med, color="grey", linestyle="--", alpha=0.6, zorder=1)
    ax.axhline(g_med, color="grey", linestyle="--", alpha=0.6, zorder=1)

    # Points + annotations
    for _, r in df.iterrows():
        fn = r["function"]
        c = FUNCTION_COLOURS.get(fn, "#888888")
        ax.scatter(r["verizon_weight_sum"], r["irish_avg_gap"],
                   s=380, c=c, edgecolors="black", linewidth=1.4, zorder=5)
        dx, dy, ha = offsets.get(fn, (10, 6, "left"))
        ax.annotate(fn,
                    (r["verizon_weight_sum"], r["irish_avg_gap"]),
                    xytext=(dx, dy), textcoords="offset points",
                    ha=ha, fontsize=11, fontweight="bold",
                    bbox=dict(boxstyle="round,pad=0.3",
                              facecolor="white", edgecolor=c, linewidth=1.2),
                    zorder=6)

    ax.set_xlim(-1.0, xmax)
    ax.set_ylim(0, ymax)
    ax.set_xlabel("Verizon-derived threat weight sum per CSF Function", labelpad=10)
    ax.set_ylabel("MTU / NCSC 2025 mean Irish SME adoption gap (%)", labelpad=10)
    ax.set_title("Per-CSF-Function Urgency Matrix\n"
                 "Upper-right = URGENT (high threat weight AND high Irish gap)",
                 pad=16)

    plt.savefig(out)
    plt.close(fig)
    return out


def fig5_enisa_corroboration(enisa: pd.DataFrame,
                             out: Path = FIG5) -> Path:
    df = enisa.copy().iloc[::-1]
    colours = ["#5B9BD5" if v == "YES" else "#BFBFBF"
               for v in df["in_verizon_weights"]]

    # Compose Y-label with the threat name plus the technique list on the next line.
    # covered_techniques may be NaN when the ENISA threat has no mapped techniques.
    def _label(row):
        base = str(row["enisa_threat"])[:38]
        techs = row["covered_techniques"]
        if pd.isna(techs) or not str(techs).strip():
            return f"{base}\n(not in weighted set)"
        return f"{base}\n({str(techs)[:60]})"

    df["ylabel"] = df.apply(_label, axis=1)

    fig, ax = plt.subplots(figsize=(13, 7))
    bars = ax.barh(df["ylabel"], df["verizon_weight_sum"], color=colours,
                   edgecolor="black", linewidth=0.7, height=0.72)
    max_val = max(df["verizon_weight_sum"].max(), 0.05)
    for bar in bars:
        w = bar.get_width()
        if w > 0:
            ax.text(w + max_val * 0.02, bar.get_y() + bar.get_height() / 2,
                    f"{w:.2f}", va="center", fontsize=10, color="#333",
                    fontweight="bold")

    ax.set_xlim(0, max_val * 1.30)
    ax.set_xlabel("Sum of Verizon-derived SME weight mapped to ENISA prime threat",
                  labelpad=10)
    ax.set_title("ENISA 2024 Prime EU Threats — Corroboration by Verizon-derived SME Weights",
                 pad=16)
    legend = [
        mpatches.Patch(color="#5B9BD5", label="Covered in weighted SME set"),
        mpatches.Patch(color="#BFBFBF", label="Not covered (see YAML notes)"),
    ]
    ax.legend(handles=legend, loc="lower right", frameon=True, framealpha=0.95)

    # Total covered footer
    covered_sum = enisa["verizon_weight_sum"].sum()
    ax.text(0.99, -0.14,
            f"Total covered: {covered_sum:.2f} = {100*covered_sum/2.77:.1f}% of total SME weight",
            transform=ax.transAxes, ha="right", fontsize=9,
            fontstyle="italic", color="#555")

    plt.savefig(out)
    plt.close(fig)
    return out


def main():
    FIGURES.mkdir(parents=True, exist_ok=True)

    print("[visualise] loading data ...")
    sme       = pd.read_csv(flt.SME_BRIDGE_CSV)
    weights   = ingest.load_sme_weights()
    coverage  = pd.read_csv(score.COVERAGE_CSV)
    combined  = pd.read_csv(irish_overlay.COMBINED_PRIORITY)
    urgency   = pd.read_csv(irish_overlay.FUNCTION_URGENCY)
    irish_gap = pd.read_csv(irish_overlay.IRISH_GAP_RANKING)
    enisa     = pd.read_csv(irish_overlay.ENISA_CORROBORATION)

    print("[visualise] rendering figures ...")
    fig1_function_tactic_heatmap(sme, weights)
    print(f"  wrote {FIG1.name}")
    fig2_top20_combined_priority(combined)
    print(f"  wrote {FIG2.name}")
    fig3_verizon_vs_irish_top10(coverage, irish_gap)
    print(f"  wrote {FIG3.name}")
    fig4_function_urgency_quadrant(urgency)
    print(f"  wrote {FIG4.name}")
    fig5_enisa_corroboration(enisa)
    print(f"  wrote {FIG5.name}")
    print("[visualise] done.")


if __name__ == "__main__":
    main()
