"""
Quick diagnostic: trace an "orphan" CSF Subcategory through the two mapping legs
to confirm it's genuinely unreachable (not a join defect).

Run from the project root with the csf-sme-coverage env active:
    python notebooks/01_trace_orphan.py
"""
from csf_sme_coverage import ingest

ORPHAN = "DE.AE-04"

csf_to_ctrl  = ingest.load_csf_to_800_53()
ctrl_to_tech = ingest.load_800_53_to_attack()

print(f"\nTracing orphan Subcategory: {ORPHAN}")
print("-" * 60)


controls = csf_to_ctrl.loc[csf_to_ctrl["subcategory"] == ORPHAN,
                           "control_id"].tolist()
print(f"Leg 1 (CSF -> 800-53): {ORPHAN} maps to {len(controls)} control(s)")
if controls:
    print(f"   Controls: {', '.join(sorted(controls))}")
else:
    print("   None - the orphan comes from Leg 1 (no 800-53 mapping at all)")


reached = ctrl_to_tech.loc[ctrl_to_tech["control_id"].isin(controls),
                           "control_id"].unique()
print(f"\nLeg 2 (800-53 -> ATT&CK): {len(reached)} of those {len(controls)} "
      f"control(s) appear in the CTID mapping")
if len(reached) > 0:
    print(f"   Reached: {', '.join(sorted(reached))}")
    print("\n=> UNEXPECTED - if any controls appear here the orphan should "
          "NOT be orphan. Investigate the bridge join.")
else:
    print("\n=> EXPECTED - all of this Subcategory's controls are outside "
          "CTID's mapping scope (probably PM/AT/IR family). Orphan is genuine.")
