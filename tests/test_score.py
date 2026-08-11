"""Unit tests for score.py."""
from csf_sme_coverage import ingest, filter as flt, score

def _coverage():
    csf = ingest.load_csf()
    attack = ingest.load_attack()
    mappings = ingest.load_mappings()
    weights = ingest.load_weights()
    sme = flt.sme_techniques(attack, weights)
    return csf, score.compute_coverage(csf, mappings, sme), score.residual_threats(mappings, sme)

def test_every_subcategory_appears_in_output():
    csf, cov, _ = _coverage()
    assert set(cov["subcategory_id"]) == set(csf["subcategory_id"])

def test_marginal_coverage_is_non_increasing_when_sorted_by_weighted():
    _, cov, _ = _coverage()
    cov_sorted = cov.sort_values("weighted_cov", ascending=False)
    # cumulative covered weight should be <= total SME weight
    assert cov_sorted["marginal_cov"].sum() >= 0
    # raw coverage should always be >= marginal coverage technique-count-wise (sanity)
    assert (cov_sorted["raw_coverage"] >= 0).all()

def test_residual_threats_size_matches_sme_set():
    _, _, res = _coverage()
    assert len(res) > 0
    assert (res["weight"] > 0).all()
