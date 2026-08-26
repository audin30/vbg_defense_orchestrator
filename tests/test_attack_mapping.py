from app.models import DetectionRule
from app.services.attack_mapping import coverage_by_tactic, seed_attack_techniques, uncovered_techniques


def test_coverage_reflects_enabled_rules_only(db_session):
    seed_attack_techniques(db_session)

    db_session.add(
        DetectionRule(name="rule 1", attack_technique_id="T1190", enabled=True)
    )
    db_session.add(
        DetectionRule(name="rule 2 (disabled)", attack_technique_id="T1566", enabled=False)
    )
    db_session.commit()

    coverage = coverage_by_tactic(db_session)

    assert coverage["Initial Access"]["covered"] == 1  # only the enabled rule counts
    assert coverage["Initial Access"]["total"] >= 2

    uncovered = {t.id for t in uncovered_techniques(db_session)}
    assert "T1566" in uncovered  # disabled rule's technique should show as a gap
    assert "T1190" not in uncovered
