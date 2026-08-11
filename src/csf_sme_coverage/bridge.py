from __future__ import annotations

from pathlib import Path
from typing import Optional

import pandas as pd

from . import ingest


ROOT      = Path(__file__).resolve().parents[2]
PROCESSED = ROOT / "data" / "processed"
BRIDGE_CSV   = PROCESSED / "bridge_full.csv"
BRIDGE_STATS = PROCESSED / "bridge_stats.txt"


def build_bridge(csf: pd.DataFrame,
                 csf_to_ctrl: pd.DataFrame,
                 ctrl_to_tech: pd.DataFrame,
                 attack: pd.DataFrame) -> pd.DataFrame:
    """Chain the two intermediate mappings into one canonical table.

    Args:
        csf:          from ingest.load_csf_subcategories()
        csf_to_ctrl:  from ingest.load_csf_to_800_53()
        ctrl_to_tech: from ingest.load_800_53_to_attack()
        attack:       from ingest.load_attack_techniques()

    Returns:
        DataFrame with columns
            subcategory, function, category,
            control_id,
            technique_id, technique_name, tactic, is_subtechnique
        deduplicated on (subcategory, technique_id).
    """
    
    step1 = csf_to_ctrl.copy()

    
    step2 = step1.merge(
        ctrl_to_tech[["control_id", "technique_id"]],
        on="control_id",
        how="inner",
    )

    unique_pairs = (step2[["subcategory", "technique_id"]]
                    .drop_duplicates()
                    .reset_index(drop=True))

    
    bridging_controls = (step2.groupby(["subcategory", "technique_id"])["control_id"]
                              .apply(lambda s: ";".join(sorted(set(s))))
                              .reset_index()
                              .rename(columns={"control_id": "via_controls"}))

    out = unique_pairs.merge(bridging_controls, on=["subcategory", "technique_id"])

    
    out = out.merge(
        csf[["subcategory", "function", "function_code", "category", "category_code"]],
        on="subcategory", how="left",
    )

    out = out.merge(
        attack[["technique_id", "technique_name", "tactic", "is_subtechnique"]],
        on="technique_id", how="left",
    )

    out = out[[
        "function_code", "function", "category_code", "category", "subcategory",
        "technique_id", "technique_name", "tactic", "is_subtechnique",
        "via_controls",
    ]]
    return out.sort_values(["subcategory", "technique_id"]).reset_index(drop=True)


# -----------------------------------------------------------------------------
# Coverage / quality report
# -----------------------------------------------------------------------------
def coverage_stats(bridge: pd.DataFrame,
                   csf: pd.DataFrame,
                   attack: pd.DataFrame) -> dict:
    """Compute join quality metrics; use to spot orphans before scoring."""
    all_subs   = set(csf["subcategory"])
    all_techs  = set(attack.loc[~attack["revoked"], "technique_id"])
    reached_subs  = set(bridge["subcategory"])
    reached_techs = set(bridge["technique_id"])

    orphan_subs  = sorted(all_subs  - reached_subs)   # Subcats with no path to any technique
    orphan_techs = sorted(all_techs - reached_techs)  # Techniques with no covering Subcategory

    per_sub_tech_count = (bridge.groupby("subcategory")["technique_id"]
                                .nunique().rename("n_techniques")).sort_values(ascending=False)
    per_tech_sub_count = (bridge.groupby("technique_id")["subcategory"]
                                .nunique().rename("n_subcategories")).sort_values(ascending=False)

    return {
        "total_pairs":        len(bridge),
        "subcats_total":      len(all_subs),
        "subcats_reached":    len(reached_subs),
        "subcats_orphan":     len(orphan_subs),
        "orphan_subcats":     orphan_subs,
        "techs_total_live":   len(all_techs),
        "techs_reached":      len(reached_techs),
        "techs_orphan":       len(orphan_techs),
        "orphan_techs_head":  orphan_techs[:10],
        "top_subs_by_techs":  per_sub_tech_count.head(10).to_dict(),
        "top_techs_by_subs":  per_tech_sub_count.head(10).to_dict(),
    }


def format_stats(s: dict) -> str:
    """Human-readable report matching the print in __main__."""
    lines = []
    lines.append("=" * 70)
    lines.append("  BRIDGE COVERAGE REPORT")
    lines.append("=" * 70)
    lines.append(f"  Total (Subcategory, Technique) pairs .. {s['total_pairs']:>6}")
    lines.append("")
    lines.append(f"  Subcategories total  .................. {s['subcats_total']:>6}")
    lines.append(f"  Subcategories reached ................. {s['subcats_reached']:>6}")
    lines.append(f"  Subcategories with NO ATT&CK path ..... {s['subcats_orphan']:>6}")
    if s["orphan_subcats"]:
        lines.append(f"    ORPHANS: {', '.join(s['orphan_subcats'])}")
    lines.append("")
    lines.append(f"  ATT&CK techniques (live) total ........ {s['techs_total_live']:>6}")
    lines.append(f"  ATT&CK techniques reached ............. {s['techs_reached']:>6}")
    lines.append(f"  ATT&CK techniques not reached ......... {s['techs_orphan']:>6}")
    lines.append(f"    (e.g. {', '.join(s['orphan_techs_head'])})")
    lines.append("")
    lines.append("  Top 10 Subcategories by breadth of ATT&CK coverage:")
    for sub, n in s["top_subs_by_techs"].items():
        lines.append(f"      {sub:<12}  addresses {n:>3} techniques")
    lines.append("")
    lines.append("  Top 10 ATT&CK techniques by breadth of CSF coverage:")
    for tech, n in s["top_techs_by_subs"].items():
        lines.append(f"      {tech:<12}  covered by {n:>3} Subcategories")
    lines.append("=" * 70)
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# CLI entry: build, save, print
# -----------------------------------------------------------------------------
def main():
    PROCESSED.mkdir(parents=True, exist_ok=True)

    print("[bridge] loading raw frames from ingest ...")
    csf          = ingest.load_csf_subcategories()
    csf_to_ctrl  = ingest.load_csf_to_800_53()
    ctrl_to_tech = ingest.load_800_53_to_attack()
    attack       = ingest.load_attack_techniques()
    print(f"[bridge]   csf={len(csf)}, csf_to_ctrl={len(csf_to_ctrl)}, "
          f"ctrl_to_tech={len(ctrl_to_tech)}, attack={len(attack)}")

    print("[bridge] joining CSF -> 800-53 -> ATT&CK ...")
    bridge = build_bridge(csf, csf_to_ctrl, ctrl_to_tech, attack)
    print(f"[bridge]   produced {len(bridge)} rows")

    print(f"[bridge] writing {BRIDGE_CSV}")
    bridge.to_csv(BRIDGE_CSV, index=False)

    stats = coverage_stats(bridge, csf, attack)
    report = format_stats(stats)
    BRIDGE_STATS.write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
