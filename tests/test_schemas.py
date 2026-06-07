"""Tests des contrats de données partagés (src.common.schemas)."""

from __future__ import annotations

import pytest

from src.common.schemas import (
    Alert,
    AlertStatus,
    Channel,
    PhishingPrediction,
    PhishingSample,
    Severity,
    VulnScore,
    Vulnerability,
)


# --------------------------------------------------------------------------- #
# Severity.from_cvss — mapping CVSS v3.1
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "score, expected",
    [
        (9.8, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.5, Severity.HIGH),
        (7.0, Severity.HIGH),
        (5.5, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.1, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
    ],
)
def test_severity_from_cvss(score, expected):
    assert Severity.from_cvss(score) is expected


# --------------------------------------------------------------------------- #
# Vulnerability — dérivation automatique de la sévérité depuis le CVSS
# --------------------------------------------------------------------------- #
def test_vulnerability_derives_severity_from_cvss():
    vuln = Vulnerability(
        id="v1",
        host="10.0.0.1",
        name="Test RCE",
        cvss_score=9.8,
        # severity volontairement non fournie -> doit être dérivée
    )
    assert vuln.severity is Severity.CRITICAL


def test_vulnerability_explicit_severity_respected():
    vuln = Vulnerability(
        id="v2",
        host="10.0.0.1",
        name="Test",
        cvss_score=2.0,
        severity=Severity.HIGH,  # explicite -> conservée
    )
    assert vuln.severity is Severity.HIGH


def test_vulnerability_requires_mandatory_fields():
    # id, host et name sont requis ; leur absence doit lever une erreur.
    with pytest.raises(Exception):
        Vulnerability(host="10.0.0.1", name="sans id")


def test_vulnerability_cvss_range_validation():
    with pytest.raises(Exception):
        Vulnerability(id="v3", host="h", name="n", cvss_score=42.0)


# --------------------------------------------------------------------------- #
# PhishingSample / Channel
# --------------------------------------------------------------------------- #
def test_phishing_sample_valid():
    s = PhishingSample(id="s1", channel=Channel.SMS, raw_text="bonjour")
    assert s.channel is Channel.SMS
    assert s.label is None
    assert s.language == "fr"


def test_phishing_sample_invalid_channel():
    with pytest.raises(Exception):
        PhishingSample(id="s1", channel="CARRIER_PIGEON", raw_text="x")


# --------------------------------------------------------------------------- #
# PhishingPrediction — bornes du score
# --------------------------------------------------------------------------- #
def test_phishing_prediction_valid():
    p = PhishingPrediction(sample_id="s1", is_phishing=True, score=0.87)
    assert 0.0 <= p.score <= 1.0
    assert p.model == "tfidf_rf"


def test_phishing_prediction_score_out_of_range():
    with pytest.raises(Exception):
        PhishingPrediction(sample_id="s1", is_phishing=True, score=1.5)


# --------------------------------------------------------------------------- #
# VulnScore
# --------------------------------------------------------------------------- #
def test_vuln_score_valid():
    vs = VulnScore(vulnerability_id="v1", ml_score=0.7)
    assert vs.priority is Severity.MEDIUM  # valeur par défaut
    assert 0.0 <= vs.ml_score <= 1.0


def test_vuln_score_requires_fields():
    with pytest.raises(Exception):
        VulnScore(ml_score=0.5)  # vulnerability_id manquant


# --------------------------------------------------------------------------- #
# Alert
# --------------------------------------------------------------------------- #
def test_alert_valid_defaults():
    a = Alert(id="a1", title="t", risk_score=72.0, severity=Severity.HIGH)
    assert a.status is AlertStatus.NEW
    assert a.vulnerability_ids == []
    assert a.phishing_sample_ids == []
    assert 0.0 <= a.risk_score <= 100.0


def test_alert_risk_score_range():
    with pytest.raises(Exception):
        Alert(id="a2", title="t", risk_score=150.0, severity=Severity.HIGH)


def test_alert_requires_mandatory_fields():
    with pytest.raises(Exception):
        Alert(title="sans id", risk_score=10.0, severity=Severity.LOW)
