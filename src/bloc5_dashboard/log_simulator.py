"""Simulateur de flux d'événements entrants et analyse temps réel (bloc 5).

Ce module produit des « événements entrants » réalistes (SMS, e-mails, URLs)
mélangeant messages légitimes et tentatives de phishing dans le contexte
camerounais, puis les analyse à la volée avec le détecteur du bloc 3.

Conception :

* AUCUN import lourd au niveau module (scikit-learn, pandas, le détecteur) :
  ils sont effectués paresseusement dans les méthodes/fonctions concernées.
* AUCUN thread ni effet de bord à l'import : la classe est purement passive.
* Repli heuristique garanti : si aucun modèle n'est entraîné, le détecteur du
  bloc 3 bascule automatiquement sur son heuristique (voir :mod:`src.bloc3_ia`).

Points d'entrée publics :
    >>> gen = EventGenerator(phishing_rate=0.25, seed=42)
    >>> event = gen.next_event()
    >>> analysed = analyze_event(event)
    >>> analysed["is_phishing"], analysed["score"]
"""

from __future__ import annotations

import random
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from src.common.logging_conf import get_logger
from src.common.schemas import Channel, PhishingSample

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Détection d'indicateurs (version légère, autonome)
# --------------------------------------------------------------------------- #
# NB : aucun module ``api/inference.py`` n'existe dans le projet ; on définit
# donc ici une extraction d'indicateurs légère et sans dépendance lourde,
# réutilisable par le flux temps réel.

_URL_RE = re.compile(r"(https?://\S+|www\.\S+|\b\S+\.(?:com|net|org|ml|tk|cm|info)\b\S*)", re.IGNORECASE)
_SHORTENER_RE = re.compile(r"\b(?:bit\.ly|tinyurl\.com|cutt\.ly|is\.gd|t\.co)\b", re.IGNORECASE)
_SUSPICIOUS_TLD_RE = re.compile(r"\.(?:ml|tk|cm-secure)\b", re.IGNORECASE)
_MONEY_RE = re.compile(r"\b\d[\d .,]*\s*(?:fcfa|xaf|francs?)\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\b6[\dX]{7,8}\b")

#: Mots-clés d'urgence / ingénierie sociale fréquents dans le phishing local.
_URGENCY_KEYWORDS = [
    "urgent", "immediatement", "immédiatement", "suspendu", "bloque", "bloqué",
    "verifiez", "vérifiez", "confirmez", "code pin", "mot de passe", "gagne",
    "gagnant", "felicitations", "félicitations", "loterie", "expire", "24h",
    "suspended", "verify", "winner", "congratulations", "click",
]


def extract_indicators(raw_text: str) -> List[str]:
    """Extrait des indicateurs explicables d'un texte (URLs, urgence, etc.).

    Args:
        raw_text: contenu brut du message/log à inspecter.

    Returns:
        Liste de chaînes décrivant les signaux détectés (peut être vide). Ces
        indicateurs sont purement explicatifs : ils enrichissent le verdict du
        modèle sans le remplacer.
    """
    text = raw_text or ""
    lower = text.lower()
    indicators: List[str] = []

    if _URL_RE.search(text):
        indicators.append("url_presente")
    if _SHORTENER_RE.search(text):
        indicators.append("raccourcisseur_url")
    if _SUSPICIOUS_TLD_RE.search(text):
        indicators.append("tld_suspect")
    if _MONEY_RE.search(text):
        indicators.append("montant_argent")
    if _PHONE_RE.search(text):
        indicators.append("numero_telephone")
    if any(kw in lower for kw in _URGENCY_KEYWORDS):
        indicators.append("vocabulaire_urgence")

    return indicators


# --------------------------------------------------------------------------- #
# Générateur d'événements entrants
# --------------------------------------------------------------------------- #
class EventGenerator:
    """Produit des « événements entrants » réalistes à analyser en temps réel.

    Chaque événement est un dictionnaire JSON-sérialisable simulant un message
    reçu par l'organisation (SMS/e-mail/URL), avec un horodatage, une adresse IP
    source simulée, un expéditeur et le texte brut. Les messages proviennent du
    générateur de corpus du bloc 2, en respectant un taux de phishing cible.

    Attributes:
        phishing_rate: probabilité qu'un événement soit issu de la classe
            phishing (entre 0.0 et 1.0).
    """

    def __init__(
        self,
        phishing_rate: float = 0.25,
        seed: Optional[int] = 42,
        pool_size: int = 120,
    ) -> None:
        """Initialise le générateur.

        Args:
            phishing_rate: proportion cible de messages phishing (def 0.25).
            seed: graine de reproductibilité (``None`` = non déterministe).
            pool_size: nombre d'échantillons par classe à pré-générer.
        """
        self.phishing_rate = max(0.0, min(1.0, float(phishing_rate)))
        self._rng = random.Random(seed)
        self._seq = 0
        # Pools séparés phishing / légitime, alimentés paresseusement.
        self._pool_size = max(10, int(pool_size))
        self._phish_pool: List[PhishingSample] = []
        self._legit_pool: List[PhishingSample] = []
        self._loaded = False

    # -- chargement paresseux des messages ---------------------------------- #
    def _ensure_pools(self) -> None:
        """Charge les viviers de messages (corpus synthétique) à la demande."""
        if self._loaded:
            return
        from src.bloc2_phishing.corpus_generator import generate_corpus

        samples = generate_corpus(n_per_class=self._pool_size, seed=self._seq or 42)
        for s in samples:
            if s.label == 1:
                self._phish_pool.append(s)
            else:
                self._legit_pool.append(s)
        # Garde-fous : si une classe est vide, on évite l'IndexError plus loin.
        if not self._phish_pool:
            self._phish_pool = list(samples)
        if not self._legit_pool:
            self._legit_pool = list(samples)
        self._loaded = True
        logger.info(
            "EventGenerator prêt : %d phishing / %d légitimes en vivier.",
            len(self._phish_pool),
            len(self._legit_pool),
        )

    def _fake_ip(self) -> str:
        """Génère une adresse IPv4 source simulée (plages privées variées)."""
        block = self._rng.choice(["10", "172", "192.168", "41", "154"])
        if block == "192.168":
            return f"192.168.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
        if block == "172":
            return f"172.{self._rng.randint(16, 31)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
        return f"{block}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"

    def _fake_sender(self, channel: Channel) -> str:
        """Construit un expéditeur plausible selon le canal."""
        if channel == Channel.EMAIL:
            user = "".join(self._rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(6))
            domain = self._rng.choice(
                ["gmail.com", "yahoo.fr", "service-client.cm", "no-reply.net", "info.org"]
            )
            return f"{user}@{domain}"
        if channel == Channel.SMS:
            return self._rng.choice(["MTN", "Orange", "+2376" + "".join(
                str(self._rng.randint(0, 9)) for _ in range(7)), "INFO"])
        return "web-crawler"

    def next_event(self) -> Dict[str, Any]:
        """Produit le prochain événement entrant (dict JSON-sérialisable).

        Returns:
            Un dictionnaire contenant : ``id``, ``ts`` (ISO 8601 UTC),
            ``source_ip``, ``channel``, ``sender``, ``raw_text`` et
            ``true_label`` (vérité terrain simulée, utile en démo).
        """
        self._ensure_pools()
        self._seq += 1

        is_phish = self._rng.random() < self.phishing_rate
        pool = self._phish_pool if is_phish else self._legit_pool
        sample = self._rng.choice(pool)
        channel = sample.channel

        return {
            "id": f"evt-{self._seq:06d}",
            "ts": datetime.now(timezone.utc).isoformat(),
            "source_ip": self._fake_ip(),
            "channel": channel.value,
            "sender": self._fake_sender(channel),
            "raw_text": sample.raw_text,
            "true_label": sample.label,
        }

    def stream(
        self, n: Optional[int] = None, delay: float = 0.0
    ) -> Iterator[Dict[str, Any]]:
        """Générateur d'événements entrants.

        Args:
            n: nombre d'événements à produire ; ``None`` = flux illimité (à
                consommer avec précaution, p. ex. via ``itertools.islice``).
            delay: pause (secondes) entre deux événements (simule le débit).

        Yields:
            Des événements bruts (dict) tels que produits par :meth:`next_event`.
        """
        import time

        produced = 0
        while n is None or produced < n:
            yield self.next_event()
            produced += 1
            if delay > 0:
                time.sleep(delay)


# --------------------------------------------------------------------------- #
# Analyse temps réel d'un événement
# --------------------------------------------------------------------------- #
def analyze_event(
    event: Dict[str, Any], detector: Optional[Any] = None
) -> Dict[str, Any]:
    """Analyse un événement entrant et l'enrichit du verdict de phishing.

    Le texte est prétraité (bloc 2) puis soumis au détecteur (bloc 3). Si aucun
    détecteur n'est fourni, on en obtient un via ``get_detector`` (repli
    heuristique garanti en l'absence de modèle entraîné).

    Args:
        event: événement brut (au minimum ``raw_text`` et ``channel``).
        detector: détecteur déjà instancié (réutilisé pour la performance) ;
            si ``None``, un détecteur est chargé paresseusement.

    Returns:
        Une COPIE enrichie de l'événement avec : ``is_phishing`` (bool),
        ``score`` (float 0-1), ``model`` (str) et ``indicators`` (list[str]).
    """
    from src.bloc2_phishing.preprocessing import clean_text

    raw_text = str(event.get("raw_text", ""))
    channel_raw = event.get("channel", Channel.SMS.value)
    try:
        channel = Channel(channel_raw)
    except ValueError:
        channel = Channel.SMS

    sample = PhishingSample(
        id=str(event.get("id", "evt-rt")),
        channel=channel,
        raw_text=raw_text,
        clean_text=clean_text(raw_text),
        source="realtime",
    )

    if detector is None:
        from src.bloc3_ia import get_detector

        detector = get_detector()

    try:
        prediction = detector.predict([sample])[0]
        is_phishing = bool(prediction.is_phishing)
        score = float(prediction.score)
        model = str(prediction.model)
    except Exception as exc:  # noqa: BLE001 — le flux ne doit jamais casser
        logger.error("Échec de l'analyse temps réel (%s) ; verdict neutre.", exc)
        is_phishing, score, model = False, 0.0, "unavailable"

    enriched = dict(event)
    enriched.update(
        {
            "is_phishing": is_phishing,
            "score": round(score, 4),
            "model": model,
            "indicators": extract_indicators(raw_text),
        }
    )
    return enriched


__all__ = ["EventGenerator", "analyze_event", "extract_indicators"]
