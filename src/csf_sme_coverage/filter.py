from __future__ import annotations

from pathlib import Path
from typing import Optional

import pandas as pd

from . import ingest, bridge

ROOT      = Path(__file__).resolve().parents[2]
PROCESSED = ROOT / "data" / "processed"
SME_BRIDGE_CSV = PROCESSED / "sme_bridge.csv"
FILTER_STATS   = PROCESSED / "filter_stats.txt"


# -----------------------------------------------------------------------------
# The SME filter
# -----------------------------------------------------------------------------
def sme_bridge(bridge_df: pd.DataFrame,
               weights: pd.DataFrame) -> pd.DataFrame:
    """Inner-join the bridge with the SME weights.

    Args:
        bridge_df: from bridge.build_bridge()
        weights:   from ingest.load_sme_weights()

    Returns:
        DataFrame with columns
            function_code, function, category_code, category, subcategory,
            technique_id, technique_name, tactic, is_subtechnique,
            via_controls, weight, weight_source
        with one row per (Subcategory, SME-relevant technique) pair.
    """
    # Preserve bridge's own technique_name; rename weights columns to avoid clash.
    w = weights.rename(columns={"name": "weight_source_name",
                                "source": "weight_source"})

    out = bridge_df.merge(
        w[["technique_id", "weight", "weight_source"]],
        on="technique_id",
        how="inner",
    )
    return out.sort_values(
        ["subcategory", "technique_id"]
    ).reset_index(drop=True)


def filter_stats(bridge_df: pd.DataFrame,
                 sme: pd.DataFrame,
                 weights: pd.DataFrame,
                 csf: pd.DataFrame) -> dict:
    """Report how the bridge collapses under the SME filter."""
    weight_techs   = set(weights["technique_id"])
    bridge_techs   = set(bridge_df["technique_id"])
    sme_techs      = set(sme["technique_id"])

    # Techniques in the weights file that never appear via the bridge
    unreached_sme_techs = sorted(weight_techs - bridge_techs)

    subs_all       = set(csf["subcategory"])
    subs_in_bridge = set(bridge_df["subcategory"])
    subs_in_sme    = set(sme["subcategory"])

    per_sub_sme_count = (sme.groupby("subcategory")["technique_id"]
                            .nunique().rename("sme_techs")
                            .sort_values(ascending=False))
    per_sub_sme_weight = (sme.groupby("subcategory")["weight"]
                             .sum().rename("total_weight")
                             .sort_values(ascending=False))

    return {
        "bridge_rows":            len(bridge_df),
        "sme_rows":               len(sme),
        "bridge_unique_techs":    len(bridge_techs),
        "weights_defined_techs":  len(weight_techs),
        "sme_reached_techs":      len(sme_techs),
        "sme_unreached_techs":    unreached_sme_techs,
        "subs_total":             len(subs_all),
        "subs_in_bridge":         len(subs_in_bridge),
        "subs_in_sme_filtered":   len(subs_in_sme),
        "top_subs_by_count":      per_sub_sme_count.head(15).to_dict(),
        "top_subs_by_weight":     per_sub_sme_weight.head(15).to_dict(),
    }


def format_stats(s: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("  FILTER (Phase 4) REPORT")
    lines.append("=" * 70)
    lines.append(f"  Bridge rows (pre-filter)    ....... {s['bridge_rows']:>6}")
    lines.append(f"  SME rows (post-filter)      ....... {s['sme_rows']:>6}")
    ratio = 100 * s['sme_rows'] / max(s['bridge_rows'], 1)
    lines.append(f"  Filter retention             ....... {ratio:>6.1f}%")
    lines.append("")
    lines.append(f"  ATT&CK techniques in bridge  ...... {s['bridge_unique_techs']:>6}")
    lines.append(f"  Techniques defined in weights .... {s['weights_defined_techs']:>6}")
    lines.append(f"  SME-relevant techniques reached .. {s['sme_reached_techs']:>6}")
    lines.append(f"  SME-relevant NOT reached ......... {len(s['sme_unreached_techs']):>6}")
    if s['sme_unreached_techs']:
        lines.append("     WARNING - the following weighted techniques are")
        lines.append("     not reachable through the CSF -> 800-53 -> ATT&CK bridge:")
        for t in s['sme_unreached_techs']:
            lines.append(f"        {t}")
        lines.append("     These represent gaps in the underlying mappings.")
        lines.append("     Discuss in dissertation Chapter 5 (limitations).")
    lines.append("")
    lines.append(f"  Subcategories reached in bridge .. {s['subs_in_bridge']:>4}/{s['subs_total']:>3}")
    lines.append(f"  Subcategories reached in SME .... {s['subs_in_sme_filtered']:>4}/{s['subs_total']:>3}")
    lines.append("")
    lines.append("  Top 15 Subcategories by number of SME-relevant techniques:")
    for sub, n in s['top_subs_by_count'].items():
        lines.append(f"      {sub:<12}  {n:>3} techniques")
    lines.append("")
    lines.append("  Top 15 Subcategories by summed weight of SME-relevant techniques:")
    for sub, w in s['top_subs_by_weight'].items():
        lines.append(f"      {sub:<12}  {w:>6.2f}")
    lines.append("=" * 70)
    return "\n".join(lines)


def main():
    PROCESSED.mkdir(parents=True, exist_ok=True)

    print("[filter] loading intermediate frames ...")
    csf     = ingest.load_csf_subcategories()
    weights = ingest.load_sme_weights()

    # If bridge_full.csv exists, load it; otherwise rebuild.
    if bridge.BRIDGE_CSV.exists():
        print(f"[filter] loading bridge from {bridge.BRIDGE_CSV.name}")
        bridge_df = pd.read_csv(bridge.BRIDGE_CSV)
    else:
        print("[filter] bridge_full.csv missing - rebuilding bridge on the fly")
        csf_to_ctrl  = ingest.load_csf_to_800_53()
        ctrl_to_tech = ingest.load_800_53_to_attack()
        attack       = ingest.load_attack_techniques()
        bridge_df    = bridge.build_bridge(csf, csf_to_ctrl, ctrl_to_tech, attack)

    print(f"[filter]   bridge={len(bridge_df)} rows, weights={len(weights)} techs")

    print("[filter] applying SME filter ...")
    sme = sme_bridge(bridge_df, weights)
    print(f"[filter]   produced {len(sme)} SME-relevant rows")

    print(f"[filter] writing {SME_BRIDGE_CSV}")
    sme.to_csv(SME_BRIDGE_CSV, index=False)

    stats  = filter_stats(bridge_df, sme, weights, csf)
    report = format_stats(stats)
    FILTER_STATS.write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
