# `data/external/` — Datasets externes (sources publiques réelles)

Ce dossier contient les datasets **réels** téléchargés depuis des sources
publiques, normalisés vers le contrat `PhishingSample`
(`id,channel,raw_text,language,label,source`). Il est consommé par
`src/bloc2_phishing/dataset_downloader.py` pour assembler le dataset
d'entraînement (`data/processed/training_dataset.csv`).

## Sources du registre

| Source (`name`) | Canal | Format | URL brute | Licence |
|---|---|---|---|---|
| `uci_sms_spam` | SMS | TSV `ham/spam \t texte` | `https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv` | UCI ML Repository / CC BY 4.0 (Almeida & Hidalgo) |
| `sms_spam_kaggle_mirror` | SMS | CSV `v1,v2` (latin-1) | `https://raw.githubusercontent.com/mohitgupta-omg/Kaggle-SMS-Spam-Collection-Dataset-/master/spam.csv` | Dérivé UCI (recherche) |
| `phishing_emails_curated` | EMAIL | CSV (texte + label) | `https://raw.githubusercontent.com/MariyaSha/phishing_emails/main/phishing_emails.csv` | Dépôt public GitHub (à vérifier) |
| `openphish_feed` | URL | TXT (1 URL/ligne) | `https://openphish.com/feed.txt` | OpenPhish community feed (gratuit, non-commercial) |
| `phishtank_online_valid` | URL | CSV (colonne `url`) | `http://data.phishtank.com/data/online-valid.csv` | PhishTank (gratuit, attribution requise) |

Fichier déjà déposé : **`sms_spam_collection.csv`** — 1064 SMS UCI réels au
format standard (904 légitimes / 160 phishing, anglais, `source=uci_sms_spam`).

## Mode hors-ligne / sandbox

Le réseau sortant est **bloqué** dans la sandbox (`requests`/`urllib` → proxy
403). En conséquence :

- `download_source(name)` tente le téléchargement via `requests` (lazy import),
  logge clairement tout échec et **retourne `None`** sans lever d'exception ;
- `load_external()` lit **tous** les fichiers déjà présents dans ce dossier
  (CSV standard via le loader, bruts TSV/TXT via les parsers dédiés) ;
- en l'absence de réseau, le pipeline fonctionne avec les fichiers présents,
  complétés par le **corpus synthétique camerounais** (`corpus_generator`),
  plafonné par `max_synthetic_ratio` (jamais source unique).

En production (réseau ouvert), `python -m scripts.download_datasets` peuplera
réellement ce dossier depuis les sources ci-dessus.

## Éthique

- Usage strictement **défensif** (entraînement/évaluation de détecteurs).
- **Aucune donnée personnelle réelle** n'est collectée ou stockée : les corpus
  publics sont des jeux de recherche / feeds publics anonymisés, et le corpus
  synthétique est entièrement fictif (numéros, montants, liens masqués).
- Respecter la **licence et l'attribution** de chaque source ci-dessus.
- Les feeds d'URLs malveillantes (PhishTank/OpenPhish) servent uniquement à
  entraîner la détection ; ne pas y accéder à des fins offensives.
