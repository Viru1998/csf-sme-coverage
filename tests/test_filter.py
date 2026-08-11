"""Unit tests for filter.py."""
from csf_sme_coverage import ingest, filter as flt

def test_sme_set_is_subset_of_attack():
    attack = ingest.load_attack()
    weights = ingest.load_weights()
    sme = flt.sme_techniques(attack, weights)
    assert set(sme["technique_id"]).issubset(set(attack["technique_id"]))

def test_sme_set_size_matches_weights():
    attack = ingest.load_attack()
    weights = ingest.load_weights()
    sme = flt.sme_techniques(attack, weights)
    expected = set(weights["technique_id"]) & set(attack["technique_id"])
    assert set(sme["technique_id"]) == expected
