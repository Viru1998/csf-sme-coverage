"""Unit tests for ingest.py - structural invariants on the loaded data."""
from csf_sme_coverage import ingest

def test_csf_loads_all_subcategories():
    df = ingest.load_csf()
    assert len(df) >= 15
    assert set(df["function"].unique()) == {"Govern","Identify","Protect","Detect","Respond","Recover"}

def test_attack_has_required_columns():
    df = ingest.load_attack()
    assert {"technique_id","name","tactic"}.issubset(df.columns)
    assert len(df) > 0
    assert df["technique_id"].is_unique

def test_mappings_only_reference_known_ids():
    csf = ingest.load_csf()
    attack = ingest.load_attack()
    mappings = ingest.load_mappings()
    unknown_subs = set(mappings["subcategory_id"]) - set(csf["subcategory_id"])
    unknown_techs = set(mappings["technique_id"]) - set(attack["technique_id"])
    assert unknown_subs == set(), f"unknown subcategories: {unknown_subs}"
    assert unknown_techs == set(), f"unknown techniques: {unknown_techs}"

def test_weights_within_valid_range():
    w = ingest.load_weights()
    assert (w["weight"] > 0).all()
    assert (w["weight"] <= 1.0).all()
