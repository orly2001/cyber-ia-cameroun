"""Acquisition et assemblage de datasets de phishing (Bloc 2).

Ce module construit le **dataset d'entraînement** du détecteur de phishing en
combinant :

1. des **sources publiques réelles** (registre :data:`SOURCES`) téléchargées via
   ``requests`` quand le réseau est ouvert (prod) ;
2. les **fichiers déjà présents** dans ``data/external/`` (mode hors-ligne /
   sandbox où le réseau sortant est bloqué — proxy 403) ;
3. le **corpus synthétique camerounais** (``corpus_generator``) en *fallback* /
   augmentation, plafonné, **jamais** comme source unique.

Conformité stricte au contrat :class:`src.common.schemas.PhishingSample`.
``pandas`` et ``requests`` sont importés de manière **paresseuse** (dans les
fonctions) afin que le module reste importable sans ces dépendances et sans
déclencher d'appel réseau à l'import.

⚠️ Éthique : aucune donnée personnelle réelle n'est collectée ni stockée. Les
sources publiques référencées sont des corpus de recherche/feeds publics ; le
synthétique est entièrement fictif. Usage **défensif** uniquement.
"""

from __future__ import annotations

import csv
import hashlib
import random
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Union

from src.common.config import EXTERNAL_DIR, PROCESSED_DIR
from src.common.logging_conf import get_logger
from src.common.schemas import Channel, PhishingSample

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Registre de sources publiques réelles
# --------------------------------------------------------------------------- #
# Chaque entrée décrit une source téléchargeable. ``parser`` indique le format
# logique attendu, exploité par :func:`_normalize_downloaded` pour mapper vers
# PhishingSample. Les URLs sont des fichiers BRUTS réels (raw GitHub / feeds).
# En sandbox ces téléchargements échouent (proxy 403) → fallback hors-ligne.
SOURCES: List[Dict] = [
    {
        "name": "uci_sms_spam",
        "url": "https://raw.githubusercontent.com/justmarkham/"
               "pycon-2016-tutorial/master/data/sms.tsv",
        "channel": "SMS",
        "format": "tsv_label_text",   # 2 colonnes: ham/spam \t texte
        "parser": "sms_tsv",
        "license": "UCI ML Repository / CC BY 4.0 (Almeida & Hidalgo)",
        "lang": "en",
        "filename": "uci_sms_spam.tsv",
    },
    {
        "name": "sms_spam_kaggle_mirror",
        "url": "https://raw.githubusercontent.com/mohitgupta-omg/"
               "Kaggle-SMS-Spam-Collection-Dataset-/master/spam.csv",
        "channel": "SMS",
        "format": "csv_v1_v2",        # colonnes v1(label), v2(texte), latin-1
        "parser": "sms_v1v2_csv",
        "license": "Dérivé UCI SMS Spam Collection (recherche)",
        "lang": "en",
        "filename": "sms_spam_kaggle.csv",
    },
    {
        "name": "phishing_emails_curated",
        "url": "https://raw.githubusercontent.com/MariyaSha/"
               "phishing_emails/main/phishing_emails.csv",
        "channel": "EMAIL",
        "format": "csv_email",        # corpus e-mails phishing labellisés
        "parser": "email_csv",
        "license": "Dépôt public GitHub (vérifier au téléchargement)",
        "lang": "en",
        "filename": "phishing_emails.csv",
    },
    {
        "name": "openphish_feed",
        "url": "https://openphish.com/feed.txt",
        "channel": "URL",
        "format": "txt_one_url_per_line",  # une URL phishing par ligne
        "parser": "url_txt",
        "license": "OpenPhish community feed (gratuit, non-commercial)",
        "lang": "en",
        "filename": "openphish_feed.txt",
    },
    {
        "name": "phishtank_online_valid",
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "channel": "URL",
        "format": "csv_phishtank",    # colonne 'url' = URLs phishing vérifiées
        "parser": "phishtank_csv",
        "license": "PhishTank (gratuit, attribution requise)",
        "lang": "en",
        "filename": "phishtank_online_valid.csv",
    },
]


def list_sources() -> List[Dict]:
    """Renvoie une copie du registre des sources publiques réelles."""
    return [dict(s) for s in SOURCES]


def _get_source(name: str) -> Optional[Dict]:
    for s in SOURCES:
        if s["name"] == name:
            return s
    return None


# --------------------------------------------------------------------------- #
# Téléchargement (lazy requests ; ne lève jamais)
# --------------------------------------------------------------------------- #

def download_source(
    name: str,
    dest_dir: Union[str, Path] = EXTERNAL_DIR,
    timeout: int = 20,
) -> Optional[Path]:
    """Tente de télécharger une source du registre via ``requests``.

    En cas d'échec réseau (sandbox / proxy 403 / source indisponible), logge un
    message clair et **retourne ``None``** (ne lève pas), afin que l'appelant
    puisse retomber sur les fichiers déjà présents dans ``data/external/``.

    Args:
        name: nom de la source (clé ``name`` du registre).
        dest_dir: dossier de destination (défaut : ``data/external/``).
        timeout: délai réseau en secondes.

    Returns:
        Le chemin du fichier téléchargé, ou ``None`` en cas d'échec.
    """
    source = _get_source(name)
    if source is None:
        logger.error("Source inconnue : %s (sources : %s)",
                     name, ", ".join(s["name"] for s in SOURCES))
        return None

    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / source["filename"]

    try:
        import requests  # import paresseux : dépendance optionnelle
    except ImportError:
        logger.warning(
            "requests indisponible ; téléchargement de '%s' ignoré "
            "(mode hors-ligne).", name)
        return None

    url = source["url"]
    logger.info("Téléchargement de '%s' depuis %s ...", name, url)
    try:
        resp = requests.get(url, timeout=timeout, stream=True)
        resp.raise_for_status()
        content = resp.content
        if not content:
            logger.warning("Réponse vide pour '%s' ; ignoré.", name)
            return None
        dest.write_bytes(content)
        logger.info("Source '%s' enregistrée : %s (%d octets).",
                    name, dest, len(content))
        return dest
    except Exception as exc:  # réseau bloqué, 403, timeout, DNS, etc.
        logger.warning(
            "Téléchargement de '%s' échoué (%s). Repli sur les fichiers "
            "déjà présents dans %s.", name, exc, dest_dir)
        return None


def download_all(
    dest_dir: Union[str, Path] = EXTERNAL_DIR,
    timeout: int = 20,
) -> Dict[str, Optional[Path]]:
    """Tente de télécharger toutes les sources (best effort, ne plante pas).

    Returns:
        dict ``{name: Path|None}`` indiquant le résultat par source.
    """
    results: Dict[str, Optional[Path]] = {}
    for source in SOURCES:
        results[source["name"]] = download_source(
            source["name"], dest_dir=dest_dir, timeout=timeout)
    n_ok = sum(1 for p in results.values() if p is not None)
    logger.info("Téléchargements : %d/%d réussis.", n_ok, len(results))
    return results


# --------------------------------------------------------------------------- #
# Détection de langue (heuristique légère FR/EN, sans dépendance)
# --------------------------------------------------------------------------- #

_FR_HINTS = {
    "votre", "vous", "compte", "merci", "cliquez", "ici", "code", "vente",
    "felicitations", "gagne", "argent", "confirmer", "confirmez", "banque",
    "client", "solde", "transfert", "recu", "reçu", "le", "la", "les", "des",
    "est", "pour", "avec", "sur", "veuillez", "numero", "numéro", "facture",
}


def _guess_language(text: str, default: str = "en") -> str:
    """Devine 'fr' ou 'en' par mots-indices fréquents (heuristique légère)."""
    if not text:
        return default
    words = re.findall(r"[a-zàâäéèêëïîôöùûüç]+", text.lower())
    if not words:
        return default
    fr_hits = sum(1 for w in words if w in _FR_HINTS)
    # Seuil prudent : on ne bascule en FR que si signal net.
    if fr_hits >= 2 or (len(words) <= 6 and fr_hits >= 1):
        return "fr"
    return default


# --------------------------------------------------------------------------- #
# Lecture des fichiers déjà présents dans data/external/
# --------------------------------------------------------------------------- #

def _normalize_label(value) -> Optional[int]:
    """Normalise un label texte/numérique en 1/0/None (gère ham/spam, etc.)."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"", "nan", "none", "null"}:
        return None
    if text in {"1", "spam", "phishing", "phish", "fraud", "malicious", "bad"}:
        return 1
    if text in {"0", "ham", "legit", "legitimate", "benign", "safe", "good"}:
        return 0
    try:
        return 1 if int(float(text)) != 0 else 0
    except (TypeError, ValueError):
        return None


def _samples_from_csv(path: Path) -> List[PhishingSample]:
    """Lit un CSV au format standard (id,channel,raw_text,language,label,source).

    Réutilise le loader existant pour rester cohérent avec le reste du projet.
    """
    from src.bloc2_phishing.loader import load_samples
    return load_samples(path)


def _samples_from_sms_tsv(path: Path, source_name: str) -> List[PhishingSample]:
    """Parse le TSV UCI brut : ``ham|spam <TAB> texte``."""
    samples: List[PhishingSample] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            label_raw, text = parts
            label = _normalize_label(label_raw)
            text = text.strip()
            if not text:
                continue
            samples.append(PhishingSample(
                id=f"{source_name}-{i:05d}",
                channel=Channel.SMS,
                raw_text=text,
                clean_text=None,
                language="en",
                label=label,
                source=source_name,
            ))
    return samples


def _samples_from_v1v2_csv(path: Path, source_name: str) -> List[PhishingSample]:
    """Parse un CSV Kaggle SMS (colonnes v1=label, v2=texte ; latin-1)."""
    samples: List[PhishingSample] = []
    raw = None
    for enc in ("utf-8", "latin-1"):
        try:
            raw = path.read_text(encoding=enc)
            break
        except UnicodeDecodeError:
            continue
    if raw is None:
        return samples
    reader = csv.reader(raw.splitlines())
    rows = list(reader)
    if not rows:
        return samples
    header = [c.strip().lower() for c in rows[0]]
    try:
        li = header.index("v1")
        ti = header.index("v2")
        start = 1
    except ValueError:
        li, ti, start = 0, 1, 0  # pas d'en-tête reconnu : positions par défaut
    for i, row in enumerate(rows[start:], 1):
        if len(row) <= max(li, ti):
            continue
        label = _normalize_label(row[li])
        text = (row[ti] or "").strip()
        if not text:
            continue
        samples.append(PhishingSample(
            id=f"{source_name}-{i:05d}",
            channel=Channel.SMS,
            raw_text=text,
            clean_text=None,
            language="en",
            label=label,
            source=source_name,
        ))
    return samples


def _samples_from_email_csv(path: Path, source_name: str) -> List[PhishingSample]:
    """Parse un CSV d'e-mails (colonnes texte/label devinées par en-tête)."""
    samples: List[PhishingSample] = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return samples
    reader = csv.DictReader(raw.splitlines())
    if reader.fieldnames is None:
        return samples
    fields = {f.strip().lower(): f for f in reader.fieldnames}
    text_col = next((fields[k] for k in
                     ("text", "body", "email", "message", "content", "raw_text")
                     if k in fields), None)
    label_col = next((fields[k] for k in
                      ("label", "class", "type", "category", "spam")
                      if k in fields), None)
    if text_col is None:
        return samples
    for i, row in enumerate(reader, 1):
        text = (row.get(text_col) or "").strip()
        if not text:
            continue
        label = _normalize_label(row.get(label_col)) if label_col else None
        samples.append(PhishingSample(
            id=f"{source_name}-{i:05d}",
            channel=Channel.EMAIL,
            raw_text=text,
            clean_text=None,
            language=_guess_language(text, default="en"),
            label=label,
            source=source_name,
        ))
    return samples


def _samples_from_url_txt(path: Path, source_name: str) -> List[PhishingSample]:
    """Parse un feed texte d'URLs phishing (une URL par ligne → label=1)."""
    samples: List[PhishingSample] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            samples.append(PhishingSample(
                id=f"{source_name}-{i:05d}",
                channel=Channel.URL,
                raw_text=url,
                clean_text=None,
                language="en",
                label=1,
                source=source_name,
            ))
    return samples


def _samples_from_phishtank_csv(path: Path, source_name: str) -> List[PhishingSample]:
    """Parse l'export PhishTank (colonne 'url' = URLs phishing vérifiées)."""
    samples: List[PhishingSample] = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return samples
    reader = csv.DictReader(raw.splitlines())
    if reader.fieldnames is None:
        return samples
    fields = {f.strip().lower(): f for f in reader.fieldnames}
    url_col = next((fields[k] for k in ("url", "raw_text") if k in fields), None)
    if url_col is None:
        return samples
    for i, row in enumerate(reader, 1):
        url = (row.get(url_col) or "").strip()
        if not url:
            continue
        samples.append(PhishingSample(
            id=f"{source_name}-{i:05d}",
            channel=Channel.URL,
            raw_text=url,
            clean_text=None,
            language="en",
            label=1,
            source=source_name,
        ))
    return samples


# Aiguillage parser logique -> fonction de parsing d'un fichier brut.
_RAW_PARSERS = {
    "sms_tsv": _samples_from_sms_tsv,
    "sms_v1v2_csv": _samples_from_v1v2_csv,
    "email_csv": _samples_from_email_csv,
    "url_txt": _samples_from_url_txt,
    "phishtank_csv": _samples_from_phishtank_csv,
}

# Mapping nom de fichier brut connu -> (parser, source_name) pour les bruts du
# registre déposés manuellement (TSV/feed/txt) qui ne sont pas au format std.
_KNOWN_RAW_FILES = {
    s["filename"]: (s["parser"], s["name"])
    for s in SOURCES if s["parser"] != "csv_std"
}


def load_external(dir: Union[str, Path] = EXTERNAL_DIR) -> List[PhishingSample]:
    """Lit TOUS les fichiers de datasets présents dans ``data/external/``.

    - Les ``.csv`` au format standard (en-tête ``id,channel,raw_text,...``) sont
      lus via le loader existant.
    - Les fichiers bruts connus du registre (TSV/txt/CSV alternatifs) sont
      parsés via le parser logique associé.
    - Concatène le tout (le dédoublonnage est fait à l'assemblage).

    Args:
        dir: dossier des datasets externes (défaut : ``data/external/``).

    Returns:
        Liste de :class:`PhishingSample` (vide si dossier absent/illisible).
    """
    directory = Path(dir)
    if not directory.exists():
        logger.warning("Dossier externe introuvable : %s", directory)
        return []

    all_samples: List[PhishingSample] = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".csv", ".tsv", ".txt"}:
            continue

        # Fichier brut connu du registre (non-format-standard) ?
        if path.name in _KNOWN_RAW_FILES:
            parser_key, source_name = _KNOWN_RAW_FILES[path.name]
            parser = _RAW_PARSERS.get(parser_key)
            if parser is not None:
                got = parser(path, source_name)
                logger.info("%d échantillon(s) lus depuis brut %s.",
                            len(got), path.name)
                all_samples.extend(got)
                continue

        # Sinon : CSV standard (cas du sms_spam_collection.csv déjà déposé).
        if path.suffix.lower() == ".csv":
            got = _samples_from_csv(path)
            logger.info("%d échantillon(s) lus depuis CSV %s.",
                        len(got), path.name)
            all_samples.extend(got)

    logger.info("Total externe : %d échantillon(s) depuis %s.",
                len(all_samples), directory)
    return all_samples


# --------------------------------------------------------------------------- #
# Dédoublonnage + assemblage du dataset d'entraînement
# --------------------------------------------------------------------------- #

def _norm_key(text: str) -> str:
    """Clé de dédoublonnage : texte normalisé (minuscule, espaces compactés)."""
    t = re.sub(r"\s+", " ", (text or "").strip().lower())
    return hashlib.sha1(t.encode("utf-8")).hexdigest()


def _dedupe(samples: List[PhishingSample]) -> List[PhishingSample]:
    """Supprime les doublons exacts (raw_text normalisé) ; garde la 1re occurrence."""
    seen: set = set()
    out: List[PhishingSample] = []
    for s in samples:
        key = _norm_key(s.raw_text)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def dataset_stats(samples: List[PhishingSample]) -> Dict:
    """Statistiques de composition d'un ensemble d'échantillons.

    Returns:
        dict avec ``total``, ``by_label``, ``by_channel``, ``by_language``,
        ``by_source``, et ``real`` vs ``synthetic`` (par la source 'synthetic').
    """
    by_label = Counter(("phishing" if s.label == 1 else
                        "legit" if s.label == 0 else "unlabeled")
                       for s in samples)
    by_channel = Counter(s.channel.value for s in samples)
    by_language = Counter(s.language for s in samples)
    by_source = Counter(s.source for s in samples)
    n_synth = sum(1 for s in samples if s.source == "synthetic")
    return {
        "total": len(samples),
        "by_label": dict(by_label),
        "by_channel": dict(by_channel),
        "by_language": dict(by_language),
        "by_source": dict(by_source),
        "synthetic": n_synth,
        "real": len(samples) - n_synth,
        "synthetic_ratio": round(n_synth / len(samples), 4) if samples else 0.0,
    }


def _write_csv(samples: List[PhishingSample], out: Path) -> Path:
    """Écrit les échantillons au format standard (ids déjà réécrits)."""
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["id", "channel", "raw_text", "language", "label", "source"])
        for s in samples:
            writer.writerow([
                s.id,
                s.channel.value,
                s.raw_text,
                s.language,
                "" if s.label is None else str(s.label),
                s.source,
            ])
    return out


def build_training_dataset(
    prefer_real: bool = True,
    max_synthetic_ratio: float = 0.25,
    seed: int = 42,
    out: Union[str, Path] = PROCESSED_DIR / "training_dataset.csv",
    external_dir: Union[str, Path] = EXTERNAL_DIR,
) -> Path:
    """Assemble le dataset d'entraînement consolidé.

    Stratégie :
        1. Charge les **données réelles** depuis ``data/external/`` (priorité si
           ``prefer_real``).
        2. Complète avec du **synthétique** (``corpus_generator``) pour ajouter
           du contexte camerounais (FR/MoMo) et/ou combler si réel insuffisant,
           en **plafonnant** la part synthétique à ``max_synthetic_ratio``.
        3. **Dédoublonne** (raw_text normalisé), **mélange** (``seed``),
           **réécrit des ids uniques** ``train-XXXXX``.
        4. Écrit un CSV au format standard et **logge la composition**.

    Args:
        prefer_real: privilégier les données réelles (toujours conservées).
        max_synthetic_ratio: part max de synthétique dans le dataset final
            (0..1). Le nombre de synthétiques ajoutés est borné en conséquence.
        seed: graine de reproductibilité (mélange + génération synthétique).
        out: chemin du CSV de sortie.
        external_dir: dossier des datasets réels.

    Returns:
        Le chemin du CSV écrit.
    """
    from src.bloc2_phishing.corpus_generator import generate_corpus

    out = Path(out)
    rng = random.Random(seed)

    # 1) Données réelles (dédoublonnées entre elles).
    real = _dedupe(load_external(external_dir))
    real = [s for s in real if (s.raw_text or "").strip()]
    rng.shuffle(real)
    logger.info("Données réelles retenues : %d (après dédoublonnage).", len(real))

    # Clés réelles déjà vues (pour ne pas réintroduire de doublon via synthétique).
    seen_keys = {_norm_key(s.raw_text) for s in real}

    # 2) Quantité de synthétique autorisée par le plafond de ratio.
    #    Si final = real + synth et synth/final <= r  =>  synth <= r*real/(1-r).
    r = max(0.0, min(float(max_synthetic_ratio), 0.95))
    if r <= 0.0:
        max_synth = 0
    else:
        max_synth = int(len(real) * r / (1.0 - r))

    # Cas dégénéré : aucun réel disponible -> le synthétique devient nécessaire
    # (on autorise alors un corpus synthétique de secours, signalé clairement).
    if not real:
        logger.warning(
            "Aucune donnée réelle dans %s ; repli COMPLET sur le corpus "
            "synthétique (mode dégradé).", external_dir)
        max_synth = 240

    synth_added: List[PhishingSample] = []
    if max_synth > 0:
        # Génère large puis tronque/dédoublonne pour atteindre max_synth uniques.
        n_per_class = max(60, (max_synth // 2) + 30)
        corpus = generate_corpus(n_per_class=n_per_class, seed=seed)
        rng.shuffle(corpus)
        for s in corpus:
            if len(synth_added) >= max_synth:
                break
            key = _norm_key(s.raw_text)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            synth_added.append(s)
        logger.info("Synthétique ajouté : %d (plafond ratio=%.2f -> max %d).",
                    len(synth_added), r, max_synth)

    # 3) Fusion, dédoublonnage final, mélange, réécriture des ids.
    combined = _dedupe(real + synth_added)
    rng.shuffle(combined)

    final: List[PhishingSample] = []
    for i, s in enumerate(combined, 1):
        final.append(s.model_copy(update={"id": f"train-{i:05d}"}))

    # 4) Écriture + log de composition.
    _write_csv(final, out)
    stats = dataset_stats(final)
    logger.info(
        "Dataset d'entraînement écrit : %s | total=%d (réel=%d, synthétique=%d, "
        "ratio_synth=%.3f)",
        out, stats["total"], stats["real"], stats["synthetic"],
        stats["synthetic_ratio"])
    logger.info("Composition : classes=%s | canaux=%s | langues=%s",
                stats["by_label"], stats["by_channel"], stats["by_language"])
    return out


__all__ = [
    "SOURCES",
    "list_sources",
    "download_source",
    "download_all",
    "load_external",
    "build_training_dataset",
    "dataset_stats",
]
