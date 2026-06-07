"""Détecteur de phishing baseline : TF-IDF + RandomForest + repli heuristique.

Le modèle s'entraîne sur les ``PhishingSample`` labellisés (bloc 2) et produit
des :class:`PhishingPrediction`. Si aucun modèle n'est entraîné ni chargé, la
méthode :meth:`predict` applique un REPLI HEURISTIQUE basé sur des mots-clés à
risque, de sorte que le pipeline fonctionne sans entraînement préalable.

Le seuil de décision (:attr:`PhishingDetector.threshold`) est, par ordre de
priorité :

1. le seuil CALIBRÉ persisté dans le ``meta.json`` du registre
   (``chosen_threshold``), choisi sur le set de VALIDATION lors de
   l'entraînement (voir :mod:`src.bloc3_ia.train`) ;
2. à défaut, ``settings.phishing_threshold`` (repli de configuration).

Tous les imports scikit-learn / joblib sont PARESSEUX.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from src.common.config import MODELS_DIR, settings
from src.common.logging_conf import get_logger
from src.common.schemas import PhishingPrediction, PhishingSample

logger = get_logger(__name__)

# Fichier de persistance du pipeline TF-IDF + RandomForest.
DEFAULT_MODEL_PATH = MODELS_DIR / "phishing_tfidf_rf.joblib"

# Mots-clés / motifs à risque pour le repli heuristique (FR/EN, contexte CM).
# Chaque entrée contribue au score ; calibré pour franchir un seuil ~0.5.
_RISK_KEYWORDS = {
    "code pin": 0.35,
    "pin": 0.15,
    "suspendu": 0.30,
    "suspended": 0.30,
    "bloque": 0.25,
    "locked": 0.25,
    "verrouille": 0.25,
    "gagne": 0.30,
    "gagnez": 0.30,
    "felicitations": 0.30,
    "congratulations": 0.30,
    "loterie": 0.25,
    "lottery": 0.25,
    "verify": 0.25,
    "verifier": 0.20,
    "confirmez": 0.20,
    "confirm": 0.20,
    "login": 0.20,
    "connexion": 0.15,
    "cliquez": 0.20,
    "click": 0.20,
    "urgent": 0.20,
    "bit.ly": 0.35,
    "tinyurl": 0.30,
}

# Domaines / TLD suspects fréquents dans le phishing local.
_SUSPICIOUS_DOMAINS = (
    ".ml",
    ".tk",
    ".ga",
    ".cf",
    "secure-login",
    "account-verify",
    "cm-secure",
    "verify",
)


class PhishingDetector:
    """Détecteur de phishing TF-IDF + RandomForest avec repli heuristique."""

    def __init__(self, model_path: Optional[Path] = None) -> None:
        """Initialise le détecteur (aucun import lourd ici).

        Args:
            model_path: chemin de persistance du modèle (par défaut dans
                ``MODELS_DIR``).
        """
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self._pipeline = None  # pipeline sklearn (vectorizer + classifieur)
        self.threshold = float(settings.phishing_threshold)
        # ``True`` si ``self.threshold`` provient d'un calibrage persisté.
        self.threshold_calibrated = False

    # ------------------------------------------------------------------ #
    # Entraînement
    # ------------------------------------------------------------------ #
    def train(self, samples: List[PhishingSample]) -> "PhishingDetector":
        """Entraîne le pipeline TF-IDF + RandomForest sur les samples labellisés.

        Args:
            samples: échantillons prétraités (``clean_text`` rempli) et
                labellisés (``label`` ∈ {0, 1}).

        Returns:
            ``self`` pour chaînage. Si aucune donnée labellisée n'est
            disponible, le pipeline reste non entraîné (repli heuristique actif).
        """
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.pipeline import Pipeline
        except ImportError:
            logger.error(
                "scikit-learn absent : entraînement impossible. "
                "Le repli heuristique reste disponible."
            )
            return self

        texts, labels = [], []
        for s in samples:
            if s.label is None:
                continue
            texts.append(s.clean_text or s.raw_text)
            labels.append(int(s.label))

        if len(set(labels)) < 2:
            logger.warning(
                "Moins de 2 classes labellisées (%d échantillon(s)) : "
                "entraînement annulé, repli heuristique conservé.",
                len(labels),
            )
            return self

        pipeline = Pipeline(
            steps=[
                (
                    "tfidf",
                    TfidfVectorizer(
                        ngram_range=(1, 2),
                        min_df=1,
                        sublinear_tf=True,
                    ),
                ),
                (
                    "clf",
                    RandomForestClassifier(
                        n_estimators=200,
                        random_state=42,
                        class_weight="balanced",
                    ),
                ),
            ]
        )
        pipeline.fit(texts, labels)
        self._pipeline = pipeline
        logger.info(
            "Modèle TF-IDF + RandomForest entraîné sur %d échantillon(s).",
            len(labels),
        )
        return self

    # ------------------------------------------------------------------ #
    # Scores bruts (utiles au calibrage du seuil)
    # ------------------------------------------------------------------ #
    def predict_scores(self, samples: List[PhishingSample]) -> List[float]:
        """Renvoie le score de phishing ∈ [0, 1] par échantillon (sans seuil).

        Expose les probabilités brutes de la classe positive (phishing), sans
        appliquer de seuil de décision. Indispensable au CALIBRAGE du seuil sur
        un set de validation (balayage des seuils) sans réentraîner le modèle.
        Si aucun pipeline ML n'est chargé, on retombe sur le score heuristique.

        Args:
            samples: échantillons (idéalement prétraités).

        Returns:
            Liste de scores ∈ [0, 1], alignée sur ``samples``.
        """
        if self._pipeline is None:
            return [
                self._heuristic_score(s.clean_text or s.raw_text) for s in samples
            ]
        texts = [s.clean_text or s.raw_text for s in samples]
        try:
            proba = self._pipeline.predict_proba(texts)
            classes = list(self._pipeline.classes_)
            pos_idx = classes.index(1) if 1 in classes else len(classes) - 1
            return [float(row[pos_idx]) for row in proba]
        except Exception as exc:  # modèle corrompu / incompatible
            logger.error("Échec du calcul des scores ML (%s) ; repli heuristique.", exc)
            return [
                self._heuristic_score(s.clean_text or s.raw_text) for s in samples
            ]

    # ------------------------------------------------------------------ #
    # Prédiction
    # ------------------------------------------------------------------ #
    def predict(self, samples: List[PhishingSample]) -> List[PhishingPrediction]:
        """Prédit le caractère phishing de chaque échantillon.

        Utilise le pipeline entraîné si disponible, sinon applique le repli
        heuristique. ``is_phishing`` est dérivé de :attr:`threshold` (seuil
        calibré si disponible, sinon ``settings.phishing_threshold``).

        Args:
            samples: échantillons (idéalement prétraités).

        Returns:
            Liste de :class:`PhishingPrediction` (un par échantillon).
        """
        if self._pipeline is not None:
            return self._predict_ml(samples)
        return self._predict_heuristic(samples)

    def _predict_ml(self, samples: List[PhishingSample]) -> List[PhishingPrediction]:
        """Prédiction via le pipeline scikit-learn entraîné."""
        try:
            scores = self.predict_scores(samples)
        except Exception as exc:  # modèle corrompu / incompatible
            logger.error("Échec de la prédiction ML (%s) ; repli heuristique.", exc)
            return self._predict_heuristic(samples)
        # Si predict_scores a basculé sur l'heuristique (pipeline KO), le modèle
        # reste annoncé comme tfidf_rf : le score reflète déjà l'état réel.
        predictions = []
        for sample, score in zip(samples, scores):
            predictions.append(
                PhishingPrediction(
                    sample_id=sample.id,
                    is_phishing=score >= self.threshold,
                    score=round(score, 4),
                    model="tfidf_rf",
                )
            )
        return predictions

    def _predict_heuristic(
        self, samples: List[PhishingSample]
    ) -> List[PhishingPrediction]:
        """Repli sans modèle : score par mots-clés / domaines à risque."""
        logger.info(
            "Repli heuristique appliqué à %d échantillon(s) (aucun modèle).",
            len(samples),
        )
        predictions = []
        for sample in samples:
            score = self._heuristic_score(sample.clean_text or sample.raw_text)
            predictions.append(
                PhishingPrediction(
                    sample_id=sample.id,
                    is_phishing=score >= self.threshold,
                    score=round(score, 4),
                    model="heuristic",
                )
            )
        return predictions

    @staticmethod
    def _heuristic_score(text: str) -> float:
        """Calcule un score de risque ∈ [0, 1] à partir de motifs connus."""
        if not text:
            return 0.0
        lowered = text.lower()
        score = 0.0
        for keyword, weight in _RISK_KEYWORDS.items():
            if keyword in lowered:
                score += weight
        for domain in _SUSPICIOUS_DOMAINS:
            if domain in lowered:
                score += 0.20
        # Présence d'une URL normalisée ou brute = signal additionnel.
        if "<url>" in lowered or "http" in lowered:
            score += 0.10
        return min(score, 1.0)

    # ------------------------------------------------------------------ #
    # Seuil calibré
    # ------------------------------------------------------------------ #
    def set_threshold(self, value: float, calibrated: bool = True) -> None:
        """Définit le seuil de décision phishing.

        Args:
            value: nouveau seuil ∈ [0, 1] (borné par sécurité).
            calibrated: marque ce seuil comme issu d'un calibrage (transparence).
        """
        self.threshold = min(max(float(value), 0.0), 1.0)
        self.threshold_calibrated = bool(calibrated)

    def _load_calibrated_threshold(self) -> None:
        """Charge le seuil calibré (``chosen_threshold``) du registre, si présent.

        Lit le ``meta.json`` de la version courante via
        :func:`src.bloc3_ia.model_registry.latest_meta`. En cas d'absence ou
        d'erreur, le seuil de configuration (``settings.phishing_threshold``)
        reste en place.
        """
        try:
            from src.bloc3_ia.model_registry import latest_meta

            meta = latest_meta("tfidf_rf") or {}
        except Exception as exc:  # registre absent / illisible
            logger.debug("Méta du registre indisponible (%s).", exc)
            return
        chosen = meta.get("chosen_threshold")
        if chosen is None:
            return
        try:
            self.set_threshold(float(chosen), calibrated=True)
            logger.info("Seuil calibré chargé depuis le registre : %.3f", self.threshold)
        except (TypeError, ValueError):
            logger.warning("chosen_threshold du registre illisible : %r", chosen)

    # ------------------------------------------------------------------ #
    # Persistance
    # ------------------------------------------------------------------ #
    def save(self, path: Optional[Path] = None) -> Optional[Path]:
        """Sauvegarde le pipeline entraîné via joblib dans ``MODELS_DIR``.

        Args:
            path: chemin cible (par défaut ``self.model_path``).

        Returns:
            Le chemin écrit, ou ``None`` si rien à sauvegarder / erreur.
        """
        if self._pipeline is None:
            logger.warning("Aucun modèle entraîné à sauvegarder.")
            return None
        try:
            import joblib
        except ImportError:
            logger.error("joblib absent : sauvegarde impossible.")
            return None

        target = Path(path) if path else self.model_path
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._pipeline, target)
        logger.info("Modèle phishing sauvegardé : %s", target)
        return target

    def load(self, path: Optional[Path] = None) -> "PhishingDetector":
        """Charge un pipeline persisté via joblib (et le seuil calibré associé).

        Ordre de résolution de la source quand ``path`` n'est pas fourni :

        1. modèle courant du registre versionné
           (``model_registry.load_current("tfidf_rf")``) ;
        2. repli sur le chemin joblib historique (``self.model_path``) pour
           compatibilité avec l'existant.

        Après chargement du pipeline, on tente de charger le seuil calibré
        (``chosen_threshold``) depuis le ``meta.json`` du registre ; à défaut, le
        seuil reste celui de la configuration.

        Args:
            path: chemin source explicite (court-circuite la résolution ci-dessus).

        Returns:
            ``self`` ; le pipeline reste ``None`` (repli heuristique) en cas
            d'absence de fichier ou d'erreur.
        """
        try:
            import joblib
        except ImportError:
            logger.error("joblib absent : chargement impossible.")
            return self

        source: Optional[Path]
        if path is not None:
            source = Path(path)
        else:
            # 1) Modèle courant du registre versionné.
            source = None
            try:
                from src.bloc3_ia.model_registry import load_current

                source = load_current("tfidf_rf")
            except Exception as exc:  # registre absent / illisible
                logger.debug("Registre indisponible (%s) ; repli historique.", exc)
            # 2) Repli sur le chemin joblib historique.
            if source is None:
                source = self.model_path

        if not source.exists():
            logger.warning("Modèle introuvable (%s) ; repli heuristique.", source)
            return self
        try:
            self._pipeline = joblib.load(source)
            logger.info("Modèle phishing chargé : %s", source)
        except Exception as exc:
            logger.error("Échec du chargement du modèle (%s) : %s", source, exc)
            self._pipeline = None
            return self

        # Le pipeline est chargé : on tente d'appliquer le seuil calibré.
        self._load_calibrated_threshold()
        return self

    @property
    def is_trained(self) -> bool:
        """Indique si un pipeline ML est chargé/entraîné."""
        return self._pipeline is not None
