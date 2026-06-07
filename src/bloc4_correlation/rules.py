"""Règles de corrélation déclaratives (Bloc 4).

Chaque règle est un objet :class:`CorrelationRule` exposant :
    - ``id``        : identifiant stable (utilisé comme ``Alert.rule_id``) ;
    - ``name``      : libellé court ;
    - ``description`` : explication métier de la règle ;
    - ``weight``    : poids [0..1] modulant la contribution de la règle au score ;
    - ``match``     : fonction de matching ``(ctx) -> RuleMatch | None``.

La fonction de matching reçoit un :class:`MatchContext` (vues indexées des
données du pipeline) et renvoie un :class:`RuleMatch` décrivant les entités
impliquées et un texte d'explication, ou ``None`` si la règle ne s'applique pas.

Aucun import lourd : pure logique Python + modèles Pydantic partagés.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from src.common.schemas import (
    Channel,
    PhishingPrediction,
    PhishingSample,
    VulnScore,
    Vulnerability,
)

# Mots-clés utilisés pour rapprocher vulnérabilités et thématiques de phishing.
_AUTH_KEYWORDS = ("login", "auth", "authentifi", "password", "mot de passe", "credential", "session")
_VERIFY_KEYWORDS = ("verify", "vérifi", "confirm", "valider", "validation", "compte", "account", "secur")
_MOMO_KEYWORDS = ("momo", "mobile money", "orange money", "mtn", "om ", "transfert", "retrait", "solde", "compte momo")
_SENSITIVE_PORTS = {21, 22, 23, 3306, 3389, 445, 1433, 5432, 6379, 27017}


# --------------------------------------------------------------------------- #
# Structures de contexte / résultat
# --------------------------------------------------------------------------- #
@dataclass
class MatchContext:
    """Vues indexées des données du pipeline, fournies à chaque règle."""

    vulnerabilities: List[Vulnerability]
    vuln_scores: Dict[str, VulnScore]          # vulnerability_id -> VulnScore
    phishing_samples: Dict[str, PhishingSample]  # sample_id -> PhishingSample
    phishing_predictions: List[PhishingPrediction]

    def phishing_samples_predicted(self) -> List[PhishingSample]:
        """Samples dont la prédiction conclut au phishing (is_phishing=True)."""
        out: List[PhishingSample] = []
        for pred in self.phishing_predictions:
            if pred.is_phishing:
                sample = self.phishing_samples.get(pred.sample_id)
                if sample is not None:
                    out.append(sample)
        return out


@dataclass
class RuleMatch:
    """Résultat positif d'une règle déclenchée."""

    rule_id: str
    vulnerability_ids: List[str] = field(default_factory=list)
    phishing_sample_ids: List[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class CorrelationRule:
    """Règle de corrélation déclarative."""

    id: str
    name: str
    description: str
    weight: float
    match: Callable[[MatchContext], Optional[RuleMatch]]


# --------------------------------------------------------------------------- #
# Aides au matching
# --------------------------------------------------------------------------- #
def _text_of(sample: PhishingSample) -> str:
    """Texte exploitable d'un sample (priorité au texte nettoyé), en minuscules."""
    return (sample.clean_text or sample.raw_text or "").lower()


def _contains_any(text: str, keywords) -> bool:
    return any(kw in text for kw in keywords)


# --------------------------------------------------------------------------- #
# R1 — Vuln web critique + phishing URL ciblant un service similaire
# --------------------------------------------------------------------------- #
def _match_r1(ctx: MatchContext) -> Optional[RuleMatch]:
    """Une vulnérabilité web (http/https) de CVSS>=7 combinée à au moins une
    campagne de phishing par URL/EMAIL détectée pousse le risque vers le haut :
    un attaquant peut exploiter la faille ET appâter les victimes."""
    web_vulns = [
        v
        for v in ctx.vulnerabilities
        if v.cvss_score >= 7.0
        and ((v.service or "").lower() in {"http", "https", "www", "web"} or (v.port in {80, 443, 8080, 8443}))
    ]
    if not web_vulns:
        return None

    url_samples = [
        s
        for s in ctx.phishing_samples_predicted()
        if s.channel in {Channel.URL, Channel.EMAIL}
    ]
    if not url_samples:
        return None

    vuln_ids = [v.id for v in web_vulns]
    sample_ids = [s.id for s in url_samples]
    expl = (
        f"{len(web_vulns)} vulnérabilité(s) web critique(s) (CVSS>=7) exposée(s) "
        f"alors que {len(url_samples)} campagne(s) de phishing URL/email actives "
        "ciblent des services similaires."
    )
    return RuleMatch("R1", vuln_ids, sample_ids, expl)


# --------------------------------------------------------------------------- #
# R2 — Pic de phishing SMS Mobile Money
# --------------------------------------------------------------------------- #
def _match_r2(ctx: MatchContext) -> Optional[RuleMatch]:
    """Plusieurs SMS Mobile Money confirmés comme phishing constituent une
    alerte sectorielle (fraude MoMo) même en l'absence de vulnérabilité."""
    momo_samples = [
        s
        for s in ctx.phishing_samples_predicted()
        if s.channel == Channel.SMS and _contains_any(_text_of(s), _MOMO_KEYWORDS)
    ]
    if len(momo_samples) < 2:  # un "pic" = au moins 2 échantillons
        return None

    sample_ids = [s.id for s in momo_samples]
    expl = (
        f"Pic de phishing SMS Mobile Money : {len(momo_samples)} message(s) frauduleux "
        "détecté(s) ciblant les services MoMo/Orange Money."
    )
    return RuleMatch("R2", [], sample_ids, expl)


# --------------------------------------------------------------------------- #
# R3 — Vuln d'authentification + phishing "verify/login"
# --------------------------------------------------------------------------- #
def _match_r3(ctx: MatchContext) -> Optional[RuleMatch]:
    """Une faille touchant l'authentification (login, gestion de session,
    identifiants) combinée à du phishing de type 'verify/login' crée un risque
    de compromission de comptes : l'hameçonnage récolte les identifiants que la
    faille permet ensuite d'exploiter."""
    auth_vulns = [
        v
        for v in ctx.vulnerabilities
        if _contains_any((v.name + " " + v.description).lower(), _AUTH_KEYWORDS)
    ]
    if not auth_vulns:
        return None

    verify_samples = [
        s
        for s in ctx.phishing_samples_predicted()
        if _contains_any(_text_of(s), _VERIFY_KEYWORDS + _AUTH_KEYWORDS)
    ]
    if not verify_samples:
        return None

    vuln_ids = [v.id for v in auth_vulns]
    sample_ids = [s.id for s in verify_samples]
    expl = (
        f"{len(auth_vulns)} vulnérabilité(s) d'authentification combinée(s) à "
        f"{len(verify_samples)} message(s) de phishing 'vérification/login' : "
        "risque élevé de vol et de réutilisation d'identifiants."
    )
    return RuleMatch("R3", vuln_ids, sample_ids, expl)


# --------------------------------------------------------------------------- #
# R4 — Service sensible exposé priorisé par un VulnScore ML élevé
# --------------------------------------------------------------------------- #
def _match_r4(ctx: MatchContext) -> Optional[RuleMatch]:
    """Un port sensible ouvert (SSH, RDP, bases de données…) priorisé par le
    modèle IA (ml_score>=0.7) doit être traité même sans pression de phishing :
    surface d'attaque directe à fort impact."""
    flagged: List[str] = []
    for v in ctx.vulnerabilities:
        if v.port in _SENSITIVE_PORTS:
            score = ctx.vuln_scores.get(v.id)
            if score is not None and score.ml_score >= 0.7:
                flagged.append(v.id)
    if not flagged:
        return None

    expl = (
        f"{len(flagged)} service(s) sensible(s) exposé(s) sur des ports critiques "
        "et fortement priorisé(s) par le modèle IA (priorité ML >= 0.7)."
    )
    return RuleMatch("R4", flagged, [], expl)


# --------------------------------------------------------------------------- #
# Registre des règles
# --------------------------------------------------------------------------- #
RULES: List[CorrelationRule] = [
    CorrelationRule(
        id="R1",
        name="Vuln web critique + phishing URL",
        description=(
            "Vulnérabilité web CVSS>=7 sur un host conjuguée à une campagne de "
            "phishing par URL/email visant un service similaire."
        ),
        weight=1.0,
        match=_match_r1,
    ),
    CorrelationRule(
        id="R2",
        name="Pic phishing SMS Mobile Money",
        description=(
            "Plusieurs SMS Mobile Money confirmés phishing : alerte sectorielle "
            "de fraude MoMo, indépendante des vulnérabilités."
        ),
        weight=0.8,
        match=_match_r2,
    ),
    CorrelationRule(
        id="R3",
        name="Vuln authentification + phishing verify/login",
        description=(
            "Faille d'authentification associée à du phishing 'vérification/login' : "
            "risque combiné de compromission de comptes."
        ),
        weight=0.9,
        match=_match_r3,
    ),
    CorrelationRule(
        id="R4",
        name="Service sensible exposé priorisé IA",
        description=(
            "Port sensible ouvert (SSH/RDP/BD…) priorisé par un VulnScore ML "
            "élevé : surface d'attaque directe à fort impact."
        ),
        weight=0.85,
        match=_match_r4,
    ),
]


__all__ = [
    "MatchContext",
    "RuleMatch",
    "CorrelationRule",
    "RULES",
]
