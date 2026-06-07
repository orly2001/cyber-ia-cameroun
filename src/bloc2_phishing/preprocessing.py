"""Nettoyage de texte adapté au phishing FR/EN et aux SMS camerounais.

Le prétraitement normalise les éléments fréquemment exploités par les attaques
locales (SMS Mobile Money MTN/Orange, e-mails bancaires) :

* mise en minuscules ;
* normalisation des URLs vers ``<URL>`` ;
* normalisation des numéros de téléphone vers ``<PHONE>`` ;
* normalisation des montants en FCFA vers ``<MONEY>`` ;
* suppression optionnelle des accents ;
* suppression de la ponctuation superflue et des espaces redondants.

Aucune dépendance externe : uniquement la bibliothèque standard (``re``,
``unicodedata``), donc importable partout.
"""

from __future__ import annotations

import re
import unicodedata
from typing import List

from src.common.logging_conf import get_logger
from src.common.schemas import PhishingSample

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Expressions régulières (compilées une seule fois)
# --------------------------------------------------------------------------- #
# URLs (http/https/ftp) ou domaines nus de type bit.ly/xxx, exemple.cm/...
_URL_RE = re.compile(
    r"(?:https?://|ftp://|www\.)\S+"
    r"|\b(?:[a-z0-9-]+\.)+(?:com|net|org|cm|ml|info|biz|ly|co|fr)\b\S*",
    re.IGNORECASE,
)

# Montants en FCFA / F CFA / F / XAF (ex. "50000 FCFA", "2 000 000 F", "1000F").
_MONEY_RE = re.compile(
    r"\b\d[\d\s.,]*\s*(?:fcfa|f\s*cfa|xaf|frs?|f)\b",
    re.IGNORECASE,
)

# Numéros de téléphone camerounais (6XXXXXXXX, +237…, masqués 69XXXXXXX) :
# séquence d'au moins 7 chiffres pouvant contenir +, espaces, tirets et X masqués.
_PHONE_RE = re.compile(
    r"(?:\+?237[\s-]?)?(?:[\dxX]{2}[\s-]?){3,}[\dxX]{2,}",
)

# Ponctuation superflue à réduire (on garde les tokens <...> intacts).
_MULTI_PUNCT_RE = re.compile(r"[!?.,;:\"'`~^*_=\\/|()\[\]{}<>]{2,}")
_WS_RE = re.compile(r"\s+")


def strip_accents(text: str) -> str:
    """Retire les accents (é -> e) via une décomposition Unicode NFKD."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


def clean_text(text: str, lang: str = "fr", remove_accents: bool = True) -> str:
    """Nettoie un texte unitaire pour la détection de phishing.

    Args:
        text: texte brut (SMS, e-mail, URL).
        lang: code langue (``'fr'`` ou ``'en'``) — réservé pour des règles
            spécifiques futures ; n'altère pas le comportement de base.
        remove_accents: si ``True``, supprime les accents (utile pour le FR SMS
            souvent saisi sans accent).

    Returns:
        Texte normalisé en minuscules avec tokens ``<URL>``, ``<PHONE>``,
        ``<MONEY>``. Chaîne vide si l'entrée est vide.
    """
    if not text:
        return ""

    out = text.strip()

    # 1) Normalisations sémantiques AVANT la mise en minuscule pour fiabilité,
    #    en remplaçant par des tokens en minuscules (uniformisés ensuite).
    out = _URL_RE.sub(" <url> ", out)
    out = _MONEY_RE.sub(" <money> ", out)
    out = _PHONE_RE.sub(" <phone> ", out)

    # 2) Mise en minuscules.
    out = out.lower()

    # 3) Suppression optionnelle des accents (sans toucher aux tokens ASCII).
    if remove_accents:
        out = strip_accents(out)

    # 4) Réduction de la ponctuation répétée (ex. "!!!" -> " ").
    out = _MULTI_PUNCT_RE.sub(" ", out)

    # 5) Suppression de la ponctuation isolée restante, hors tokens <...>.
    #    Les tokens sont protégés par des marqueurs alphanumériques (donc
    #    préservés par les classes \w), puis restaurés en fin de traitement.
    out = out.replace("<url>", " urltoken ")
    out = out.replace("<phone>", " phonetoken ")
    out = out.replace("<money>", " moneytoken ")
    if remove_accents:
        out = re.sub(r"[^\w\s]", " ", out)
    else:
        out = re.sub(r"[^\w\sàâäéèêëïîôöùûüç]", " ", out)
    out = out.replace("urltoken", "<URL>")
    out = out.replace("phonetoken", "<PHONE>")
    out = out.replace("moneytoken", "<MONEY>")

    # 6) Normalisation finale des espaces.
    out = _WS_RE.sub(" ", out).strip()
    return out


def preprocess(samples: List[PhishingSample]) -> List[PhishingSample]:
    """Remplit ``clean_text`` pour chaque échantillon.

    Args:
        samples: liste de :class:`PhishingSample` (issus de ``load_samples``).

    Returns:
        La même liste, chaque élément voyant son champ ``clean_text`` rempli à
        partir de ``raw_text`` selon sa langue.
    """
    for sample in samples:
        sample.clean_text = clean_text(sample.raw_text, lang=sample.language)
    logger.info("Prétraitement appliqué à %d échantillon(s).", len(samples))
    return samples
