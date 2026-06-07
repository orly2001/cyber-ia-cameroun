"""Tests du moteur de corrélation (bloc 4) sur des objets construits à la main.

Ces tests n'utilisent AUCUNE dépendance externe (ni IA, ni BDD) : ils valident
la logique pure de :func:`correlate` et de :func:`compute_risk`.
"""

from __future__ import annotations

from src.bloc4_correlation import correlate
from src.bloc4_correlation.risk_engine import compute_risk
from src.common.schemas import (
    Alert,
    Channel,
    PhishingPrediction,
    PhishingSample,
    Severity,
    VulnScore,
    Vulnerability,
)


def _build_dataset():
    """1 vuln web critique + 1 vuln auth + 2 samples phishing MoMo."""
    vulns = [
        Vulnerability(
            id="v-web",
            host="10.10.0.21",
            port=80,
            service="http",
            name="Apache RCE",
            description="Apache httpd path traversal & RCE",
            cve_id="CVE-2021-41773",
            cvss_score=9.8,
            source="nvd",
        ),
        Vulnerability(
            id="v-ssh",
            host="10.10.0.21",
            port=22,
            service="ssh",
            name="Authentification SSH faible",
            description="Le service accepte des mots de passe faibles (login).",
            cvss_score=7.5,
            source="nmap",
        ),
    ]
    vuln_scores = [
        VulnScore(vulnerability_id="v-web", ml_score=0.92, priority=Severity.CRITICAL),
        VulnScore(vulnerability_id="v-ssh", ml_score=0.80, priority=Severity.HIGH),
    ]
    samples = [
        PhishingSample(
            id="s1",
            channel=Channel.SMS,
            raw_text="MTN MoMo: compte suspendu, confirmez votre code PIN",
            clean_text="mtn momo compte suspendu confirmez votre code pin verify",
            label=1,
        ),
        PhishingSample(
            id="s2",
            channel=Channel.SMS,
            raw_text="Orange Money: validez le retrait, login requis",
            clean_text="orange money validez le retrait login requis verify",
            label=1,
        ),
        PhishingSample(
            id="s3",
            channel=Channel.EMAIL,
            raw_text="Verify your bank account login at http://secure-login.ml",
            clean_text="verify your bank account login at <url> secure-login.ml",
            label=1,
        ),
    ]
    predictions = [
        PhishingPrediction(sample_id="s1", is_phishing=True, score=0.95),
        PhishingPrediction(sample_id="s2", is_phishing=True, score=0.90),
        PhishingPrediction(sample_id="s3", is_phishing=True, score=0.88),
    ]
    return vulns, vuln_scores, samples, predictions


def test_correlate_produces_alerts():
    vulns, scores, samples, preds = _build_dataset()
    alerts = correlate(vulns, scores, samples, preds)

    assert isinstance(alerts, list)
    assert len(alerts) >= 1
    for a in alerts:
        assert isinstance(a, Alert)
        assert 0.0 <= a.risk_score <= 100.0
        assert a.severity in set(Severity)
        assert a.rule_id is not None
        assert a.recommended_actions  # au moins une action proposée


def test_correlate_triggers_momo_rule_r2():
    """2 SMS MoMo confirmés phishing -> la règle R2 doit se déclencher."""
    vulns, scores, samples, preds = _build_dataset()
    alerts = correlate(vulns, scores, samples, preds)
    rule_ids = {a.rule_id for a in alerts}
    assert "R2" in rule_ids


def test_correlate_sorted_by_risk_desc():
    vulns, scores, samples, preds = _build_dataset()
    alerts = correlate(vulns, scores, samples, preds)
    risks = [a.risk_score for a in alerts]
    assert risks == sorted(risks, reverse=True)


def test_correlate_empty_inputs_no_crash():
    assert correlate([], [], [], []) == []


def test_compute_risk_bounds():
    vulns, scores, samples, preds = _build_dataset()
    scores_by_id = {s.vulnerability_id: s for s in scores}
    risk = compute_risk(scores_by_id, preds, vulns, samples)
    assert 0.0 <= risk <= 100.0


def test_compute_risk_zero_on_empty():
    assert compute_risk({}, [], [], []) == 0.0


def test_alert_ids_are_stable():
    """Le même jeu de données doit produire les mêmes ids (upsert idempotent)."""
    vulns, scores, samples, preds = _build_dataset()
    a1 = correlate(vulns, scores, samples, preds)
    a2 = correlate(vulns, scores, samples, preds)
    assert [a.id for a in a1] == [a.id for a in a2]
