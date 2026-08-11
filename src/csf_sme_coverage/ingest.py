from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import pandas as pd
import openpyxl


ROOT = Path(__file__).resolve().parents[2]
RAW  = ROOT / "data" / "raw"

CSF_JSON       = RAW / "csf2_core.json"
CROSSWALK_XLSX = RAW / "csf2_to_800_53_rev5.xlsx"
CTID_JSON      = RAW / "ctid_nist800_53_attack16.1.json"
ATTACK_JSON    = RAW / "enterprise-attack-16.1.json"
SME_WEIGHTS    = RAW / "sme_weights.yml"   # written in task #25

# Pattern to identify a canonical CSF 2.0 Subcategory ID, e.g. "GV.OC-01"
SUBCATEGORY_RE = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d+$")


def load_csf_subcategories(path: Optional[Path] = None) -> pd.DataFrame:
    """Return one row per active CSF 2.0 Subcategory.

    The exported JSON contains all element types from the CSF spec:
        function, category, subcategory, implementation_example, withdraw_reason, party

    We keep only `subcategory` entries that have a canonical ID pattern
    (e.g. GV.OC-01) and that do NOT have a corresponding `withdraw_reason`
    entry. That yields the 106 active CSF 2.0 Subcategories.

    Columns: subcategory, function, function_code, category, category_code, description
    """
    p = path or CSF_JSON
    data = json.loads(p.read_text(encoding="utf-8"))
    elements = data["response"]["elements"]["elements"]
    
    def _label(e):
        return (e.get("title") or e.get("text") or e.get("element_identifier", "")).strip()

    functions  = {e["element_identifier"]: _label(e)
                  for e in elements if e.get("element_type") == "function"}
    categories = {e["element_identifier"]: _label(e)
                  for e in elements if e.get("element_type") == "category"}
    
    withdrawn = {
        e["element_identifier"][3:]               # strip "WR-"
        for e in elements
        if e.get("element_type") == "withdraw_reason"
        and e.get("element_identifier", "").startswith("WR-")
    }

    rows = []
    for e in elements:
        if e.get("element_type") != "subcategory":
            continue
        sid = e["element_identifier"]
        if not SUBCATEGORY_RE.match(sid):
            continue                              
        if sid in withdrawn:
            continue                              

        # Subcategory like "GV.OC-01" -> Function "GV", Category "GV.OC"
        fn_code  = sid.split(".")[0]
        cat_code = sid.split("-")[0]
        rows.append({
            "subcategory":  sid,
            "function":     functions.get(fn_code, fn_code),
            "function_code": fn_code,
            "category":     categories.get(cat_code, cat_code),
            "category_code": cat_code,
            "description":  (e.get("text") or e.get("title") or "").strip(),
        })

    df = (pd.DataFrame(rows)
            .drop_duplicates("subcategory")
            .sort_values("subcategory")
            .reset_index(drop=True))
    return df


def load_csf_to_800_53(path: Optional[Path] = None) -> pd.DataFrame:
    """Parse the NIST Concept Crosswalk Excel into a long-form table.

    Columns A/C of the "Relationships" sheet are CSF element id / 800-53 control id.
    We keep only rows where the CSF id is a canonical Subcategory.

    Columns: subcategory, control_id
    """
    p = path or CROSSWALK_XLSX
    wb = openpyxl.load_workbook(p, read_only=True, data_only=True)
    ws = wb["Relationships"]

    rows = []
    for i, row in enumerate(ws.iter_rows(values_only=True)):
        if i == 0:
            continue
        csf, _, ctrl, *_ = row
        if not (csf and ctrl):
            continue
        csf_s = str(csf).strip()
        if not SUBCATEGORY_RE.match(csf_s):
            continue
        ctrl_s = str(ctrl).strip().replace("\n", "")
        rows.append({"subcategory": csf_s, "control_id": ctrl_s})

    df = (pd.DataFrame(rows)
            .drop_duplicates()
            .sort_values(["subcategory", "control_id"])
            .reset_index(drop=True))
    return df


def load_800_53_to_attack(path: Optional[Path] = None) -> pd.DataFrame:
    """Parse the CTID 800-53 Rev 5 to ATT&CK mapping JSON.

    Columns: control_id, technique_id, technique_name, mapping_type
    """
    p = path or CTID_JSON
    data = json.loads(p.read_text(encoding="utf-8"))
    rows = []
    for m in data["mapping_objects"]:
        ctrl = m.get("capability_id")
        tech = m.get("attack_object_id")
        if not (ctrl and tech):
            continue
        rows.append({
            "control_id":     str(ctrl).strip(),
            "technique_id":   str(tech).strip(),
            "technique_name": (m.get("attack_object_name") or "").strip(),
            "mapping_type":   m.get("mapping_type") or "",
        })
    df = (pd.DataFrame(rows)
            .drop_duplicates()
            .sort_values(["control_id", "technique_id"])
            .reset_index(drop=True))
    return df



def load_attack_techniques(path: Optional[Path] = None) -> pd.DataFrame:
    """Extract attack-pattern objects from the STIX bundle.

    Columns: technique_id, technique_name, tactic, is_subtechnique, parent_technique_id, revoked
    """
    p = path or ATTACK_JSON
    data = json.loads(p.read_text(encoding="utf-8"))

    rows = []
    for o in data["objects"]:
        if o.get("type") != "attack-pattern":
            continue
        # The "external_id" in the mitre-attack external_reference is the technique ID
        tech_id = None
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break
        if not tech_id:
            continue

        # Tactics are listed in kill_chain_phases (phase_name)
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]

        is_sub = bool(o.get("x_mitre_is_subtechnique", False))
        parent = tech_id.split(".")[0] if is_sub else tech_id

        rows.append({
            "technique_id":         tech_id,
            "technique_name":       o.get("name", "").strip(),
            "tactic":               ", ".join(tactics),
            "is_subtechnique":      is_sub,
            "parent_technique_id":  parent,
            "revoked":              bool(o.get("revoked", False)),
        })

    df = (pd.DataFrame(rows)
            .drop_duplicates("technique_id")
            .sort_values("technique_id")
            .reset_index(drop=True))
    return df


def load_sme_weights(path: Optional[Path] = None) -> pd.DataFrame:
    """Read the manually-curated SME technique weights from data/raw/sme_weights.yml.

    The YAML structure is::

        weights:
          - technique_id: T1566.001
            weight: 0.18
            source: "Verizon DBIR 2026 - Social Engineering"
          - ...

    Columns: technique_id, weight, source
    """
    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML not installed - run: pip install pyyaml")
    p = path or SME_WEIGHTS
    if not p.exists():
        # graceful empty so other code can still run
        return pd.DataFrame(columns=["technique_id", "weight", "source"])
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    rows = data.get("weights", [])
    df = (pd.DataFrame(rows)
            .drop_duplicates("technique_id")
            .reset_index(drop=True))
    return df


def load_all() -> dict:
    """Return a dict of all loaded raw frames. Useful in notebooks."""
    return {
        "csf":            load_csf_subcategories(),
        "csf_to_800_53":  load_csf_to_800_53(),
        "ctid_800_53":    load_800_53_to_attack(),
        "attack":         load_attack_techniques(),
        "sme_weights":    load_sme_weights(),
    }


# Quick CLI sanity check: `python -m csf_sme_coverage.ingest`
if __name__ == "__main__":
    for name, df in load_all().items():
        print(f"{name:20s}  rows={len(df):>6d}   cols={list(df.columns)}")
