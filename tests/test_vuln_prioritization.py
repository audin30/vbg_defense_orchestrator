import pytest

from app.models import Asset, Exposure, Vulnerability
from app.services.vuln_prioritization import compute_risk_score


def _asset(**overrides):
    defaults = dict(hostname="h", ip_address="10.0.0.1", criticality=3, exposure=Exposure.INTERNAL, data_sensitivity=3)
    defaults.update(overrides)
    return Asset(**defaults)


def _vuln(**overrides):
    defaults = dict(cve_id="CVE-0000-0000", title="test", cvss_score=7.0, epss_score=0.1, kev_listed=False)
    defaults.update(overrides)
    return Vulnerability(**defaults)


def test_compute_risk_score_not_yet_implemented():
    """Placeholder confirming the TODO is still in place. Once you implement
    compute_risk_score() in app/services/vuln_prioritization.py, delete this
    test and un-skip the ones below."""
    with pytest.raises(NotImplementedError):
        compute_risk_score(_vuln(), _asset())


@pytest.mark.skip(reason="un-skip once compute_risk_score() is implemented")
def test_internet_facing_scores_higher_than_isolated_for_same_cvss():
    vuln = _vuln(cvss_score=8.0)
    internet_facing = _asset(exposure=Exposure.INTERNET_FACING, criticality=3)
    isolated = _asset(exposure=Exposure.ISOLATED, criticality=3)

    assert compute_risk_score(vuln, internet_facing) > compute_risk_score(vuln, isolated)


@pytest.mark.skip(reason="un-skip once compute_risk_score() is implemented")
def test_higher_asset_criticality_increases_score():
    vuln = _vuln(cvss_score=6.0)
    low_crit = _asset(criticality=1)
    high_crit = _asset(criticality=5)

    assert compute_risk_score(vuln, high_crit) > compute_risk_score(vuln, low_crit)


@pytest.mark.skip(reason="un-skip once compute_risk_score() is implemented")
def test_kev_listed_vuln_scores_higher_than_equivalent_non_kev():
    asset = _asset()
    kev_vuln = _vuln(cvss_score=7.0, kev_listed=True)
    non_kev_vuln = _vuln(cvss_score=7.0, kev_listed=False)

    assert compute_risk_score(kev_vuln, asset) > compute_risk_score(non_kev_vuln, asset)
