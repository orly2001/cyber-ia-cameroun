"""Scoring de priorisation des vulnérabilités (bloc 1 -> bloc 3).

:class:`VulnScorer` transforme une ``list[Vulnerability]`` en
``list[VulnScore]`` (priorité ML normalisée + sévérité).

Feature engineering :
    * ``cvss_score`` (0-10) — signal principal ;
    * présence d'un ``cve_id`` — vulnérabilité connue/documentée ;
    * port exposé — exposition réseau ;
    * service -> risque — mapping qualitatif (http, ssh, rdp…).

Modèles : RandomForest (baseline) et option XGBoost (lazy import, repli si
absent). Si AUCUN modèle n'est entraîné, un REPLI HEURISTIQUE déterministe
calcule un score à partir du CVSS pondéré par le contexte, afin que le pipeline
tourne sans entraînement. Tous les imports lourds sont PARESSEUX.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from src.common.config import MODELS_DIR
from src.common.logging_conf import get_logger
from src.common.schemas import Severity, VulnScore, Vulnerability

logger = get_logger(__name__)

DEFAULT_MODEL_PATH = MODELS_DIR / "vuln_rf.joblib"

# Mapping service -> facteur de risque contextuel ∈ [0, 1].
_SERVICE_RISK = {
    "rdp": 1.0,
    "ms-wbt-server": 1.0,
    "smb": 0.95,
    "microsoft-ds": 0.95,
    "telnet": 0.95,
    "ftp": 0.85,
    "ssh": 0.75,
    "mysql": 0.80,
    "postgresql": 0.80,
    "mssql": 0.85,
    "redis": 0.85,
    "mongodb": 0.85,
    "http": 0.70,
    "https": 0.65,
    "dns": 0.60,
    "smtp": 0.65,
}
_DEFAULT_SERVICE_RISK = 0.50

# Ports sensibles fréquemment exploités.
_HIGH_RISK_PORTS = {3389, 445, 23, 21, 3306, 5432, 6379, 27017, 1433, 5900}


class VulnScorer:
    """Priorise les vulnérabilités (RandomForest / XGBoost / repli heuristique)."""

    def __init__(
        self,
        model_path: Optional[Path] = None,
        use_xgboost: bool = False,
    ) -> None:
        """Initialise le scorer (aucun import lourd ici).

        Args:
            model_path: chemin de persistance (par défaut dans ``MODELS_DIR``).
            use_xgboost: si ``True``, tente XGBoost à l'entraînement (repli RF
                ou heuristique si la lib est absente).
        """
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.use_xgboost = use_xgboost
        self._model = None  # estimateur sklearn / xgboost
        self._model_name = "heuristic"  # rf_vuln | xgboost_vuln | heuristic

    # ------------------------------------------------------------------ #
    # Feature engineering
    # ------------------------------------------------------------------ #
    @staticmethod
    def _service_risk(service: Optional[str]) -> float:
        """Facteur de risque ∈ [0, 1] dérivé du nom de service."""
        if not service:
            return _DEFAULT_SERVICE_RISK
        return _SERVICE_RISK.get(service.strip().lower(), _DEFAULT_SERVICE_RISK)

    @classmethod
    def _features(cls, vuln: Vulnerability) -> List[float]:
        """Vecteur de features numériques pour un :class:`Vulnerability`.

        Returns:
            ``[cvss_norm, has_cve, port_exposed, high_risk_port, service_risk]``.
        """
        cvss_norm = (vuln.cvss_score or 0.0) / 10.0
        has_cve = 1.0 if vuln.cve_id else 0.0
        port_exposed = 1.0 if vuln.port else 0.0
        high_risk_port = 1.0 if (vuln.port in _HIGH_RISK_PORTS) else 0.0
        service_risk = cls._service_risk(vuln.service)
        return [cvss_norm, has_cve, port_exposed, high_risk_port, service_risk]

    # ------------------------------------------------------------------ #
    # Entraînement
    # ------------------------------------------------------------------ #
    def train(
        self,
        vulns: List[Vulnerability],
        targets: Optional[List[float]] = None,
    ) -> "VulnScorer":
        """Entraîne un régressseur de priorité sur les vulnérabilités.

        Args:
            vulns: vulnérabilités d'entraînement.
            targets: scores de priorité cibles ∈ [0, 1] (un par vuln). Si
                ``None``, des cibles pseudo-labels sont dérivées du score
                heuristique (apprentissage faiblement supervisé pour démarrer).

        Returns:
            ``self``. En cas d'absence de dépendances ou de données, le scorer
            reste en mode heuristique.
        """
        if not vulns:
            logger.warning("Aucune vulnérabilité fournie : entraînement annulé.")
            return self

        X = [self._features(v) for v in vulns]
        y = targets if targets is not None else [self._heuristic_score(v) for v in vulns]

        model, name = self._build_estimator()
        if model is None:
            logger.error("Aucun backend ML disponible ; repli heuristique conservé.")
            return self

        try:
            model.fit(X, y)
        except Exception as exc:
            logger.error("Échec d'entraînement (%s) ; repli heuristique.", exc)
            return self

        self._model = model
        self._model_name = name
        logger.info(
            "Scorer de vulnérabilités entraîné (%s) sur %d échantillon(s).",
            name,
            len(vulns),
        )
        return self

    def _build_estimator(self):
        """Construit le régresseur demandé (XGBoost si possible, sinon RF)."""
        if self.use_xgboost:
            try:
                from xgboost import XGBRegressor

                return (
                    XGBRegressor(
                        n_estimators=200,
                        max_depth=4,
                        learning_rate=0.1,
                        random_state=42,
                        objective="reg:squarederror",
                    ),
                    "xgboost_vuln",
                )
            except ImportError:
                logger.warning("xgboost absent ; repli sur RandomForest.")

        try:
            from sklearn.ensemble import RandomForestRegressor

            return (
                RandomForestRegressor(n_estimators=200, random_state=42),
                "rf_vuln",
            )
        except ImportError:
            return (None, "heuristic")

    # ------------------------------------------------------------------ #
    # Scoring / prédiction
    # ------------------------------------------------------------------ #
    def score(self, vulns: List[Vulnerability]) -> List[VulnScore]:
        """Calcule les scores de priorité ML pour des vulnérabilités.

        Utilise le modèle entraîné si disponible, sinon le repli heuristique
        déterministe. La priorité (:class:`Severity`) est dérivée du score via
        ``Severity.from_cvss`` (score ramené sur une échelle 0-10).

        Args:
            vulns: vulnérabilités à prioriser.

        Returns:
            Liste de :class:`VulnScore` (une par vulnérabilité).
        """
        if self._model is not None:
            return self._score_ml(vulns)
        return self._score_heuristic(vulns)

    # Alias d'interface homogène avec les détecteurs de phishing.
    predict = score

    def _score_ml(self, vulns: List[Vulnerability]) -> List[VulnScore]:
        """Scoring via le modèle ML entraîné."""
        X = [self._features(v) for v in vulns]
        try:
            raw = self._model.predict(X)
        except Exception as exc:
            logger.error("Échec de prédiction ML (%s) ; repli heuristique.", exc)
            return self._score_heuristic(vulns)

        results = []
        for vuln, value in zip(vulns, raw):
            ml_score = max(0.0, min(1.0, float(value)))
            results.append(self._make_score(vuln, ml_score, self._model_name))
        return results

    def _score_heuristic(self, vulns: List[Vulnerability]) -> List[VulnScore]:
        """Repli déterministe : score normalisé basé sur le CVSS pondéré."""
        logger.info(
            "Repli heuristique de scoring appliqué à %d vulnérabilité(s).",
            len(vulns),
        )
        return [
            self._make_score(v, self._heuristic_score(v), "heuristic") for v in vulns
        ]

    @classmethod
    def _heuristic_score(cls, vuln: Vulnerability) -> float:
        """Score déterministe ∈ [0, 1] = CVSS normalisé pondéré par contexte."""
        feats = cls._features(vuln)
        cvss_norm, has_cve, port_exposed, high_risk_port, service_risk = feats
        # Le CVSS porte l'essentiel ; le contexte module à la hausse.
        score = (
            0.65 * cvss_norm
            + 0.10 * has_cve
            + 0.05 * port_exposed
            + 0.10 * high_risk_port
            + 0.10 * service_risk
        )
        return max(0.0, min(1.0, score))

    @staticmethod
    def _make_score(
        vuln: Vulnerability, ml_score: float, model_name: str
    ) -> VulnScore:
        """Construit un :class:`VulnScore` avec priorité dérivée du score."""
        ml_score = max(0.0, min(1.0, float(ml_score)))
        # Priorité dérivée du score ML ramené sur l'échelle CVSS (0-10).
        priority = Severity.from_cvss(ml_score * 10.0)
        return VulnScore(
            vulnerability_id=vuln.id,
            ml_score=round(ml_score, 4),
            priority=priority,
            model=model_name,
        )

    # ------------------------------------------------------------------ #
    # Persistance
    # ------------------------------------------------------------------ #
    def save(self, path: Optional[Path] = None) -> Optional[Path]:
        """Sauvegarde le modèle entraîné via joblib dans ``MODELS_DIR``."""
        if self._model is None:
            logger.warning("Aucun modèle de scoring à sauvegarder.")
            return None
        try:
            import joblib
        except ImportError:
            logger.error("joblib absent : sauvegarde impossible.")
            return None

        target = Path(path) if path else self.model_path
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "name": self._model_name}, target)
        logger.info("Modèle de scoring sauvegardé : %s", target)
        return target

    def load(self, path: Optional[Path] = None) -> "VulnScorer":
        """Charge un modèle de scoring persisté via joblib."""
        try:
            import joblib
        except ImportError:
            logger.error("joblib absent : chargement impossible.")
            return self

        source = Path(path) if path else self.model_path
        if not source.exists():
            logger.warning("Modèle introuvable (%s) ; repli heuristique.", source)
            return self
        try:
            payload = joblib.load(source)
            self._model = payload.get("model")
            self._model_name = payload.get("name", "rf_vuln")
            logger.info("Modèle de scoring chargé : %s", source)
        except Exception as exc:
            logger.error("Échec du chargement (%s) : %s", source, exc)
            self._model = None
            self._model_name = "heuristic"
        return self

    @property
    def is_trained(self) -> bool:
        """Indique si un modèle ML est chargé/entraîné."""
        return self._model is not None
