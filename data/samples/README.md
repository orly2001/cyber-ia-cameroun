# Échantillons de phishing — corpus camerounais (Bloc 2)

Ce dossier contient les jeux de données de messages utilisés par le **Bloc 2
(collecte & prétraitement)** pour entraîner et évaluer le détecteur de phishing
(Bloc 3).

Tous les fichiers respectent le contrat
[`PhishingSample`](../../src/common/schemas.py) et le format CSV attendu par
[`loader.load_samples`](../../src/bloc2_phishing/loader.py) :

| Colonne     | Description                                              |
|-------------|----------------------------------------------------------|
| `id`        | Identifiant unique (ex. `s001`, `gen-0001`)              |
| `channel`   | `SMS` \| `EMAIL` \| `URL`                                |
| `raw_text`  | Contenu brut du message ou de l'URL                      |
| `language`  | Code ISO 639-1 (`fr`, `en`)                              |
| `label`     | `1` = phishing, `0` = légitime, vide = non labellisé    |
| `source`    | Provenance (`terrain`, `phishtank`, `synthetic`, …)     |

Le loader gère deux variantes de mise en forme :
`skipinitialspace=True` ignore les espaces de remplissage après les virgules et
les en-têtes sont nettoyés (`strip`).

---

## Fichiers

### `phishing_samples_cm.csv` — échantillons de référence (10 lignes)

Petit jeu d'exemples **aligné à la main** (colonnes paddées avec des espaces
pour la lisibilité). Il sert de référence/format canonique et illustre les cas
réels typiques du contexte camerounais : SMS MTN MoMo / Orange Money, e-mails
bancaires (Afriland, UBA, Ecobank), URLs typosquattées, et messages légitimes
(ENEO, CAMTEL).

> ⚠️ Ne pas reformater ce fichier : l'alignement par espaces est volontaire et
> reste lu correctement grâce à `skipinitialspace`.

### `phishing_corpus_synth.csv` — corpus synthétique étendu (~240 lignes)

Corpus **généré automatiquement** par
[`corpus_generator.py`](../../src/bloc2_phishing/corpus_generator.py), équilibré
entre phishing (`label=1`) et messages légitimes (`label=0`). Il complète le
petit jeu de référence pour permettre l'entraînement de modèles.

**Régénération** (reproductible, graine fixe) :

```bash
# depuis la racine du projet
python -m scripts.generate_corpus
# options : --n-per-class 120 --seed 42 --output data/samples/phishing_corpus_synth.csv
```

**Composition** (`n_per_class=120`, `seed=42`) :

- 240 échantillons au total (120 phishing / 120 légitimes) ;
- multilingue : français majoritaire + anglais ;
- trois canaux : `SMS` (majoritaire), `EMAIL`, `URL` ;
- identifiants `gen-XXXX`, `source=synthetic` ;
- contrairement au CSV de référence, l'export n'aligne pas les colonnes
  (séparateur `,` standard, échappement géré par le module `csv`).

Scénarios couverts :

- **Phishing** — SMS Mobile Money (compte suspendu, gain loterie, demande de
  code PIN, faux transfert reçu), e-mails bancaires usurpés (Afriland, UBA,
  Ecobank, BICEC, …) et faux services, URLs typosquattées (`.ml`, `.tk`,
  `cm-secure`) et raccourcisseurs.
- **Légitime** — notifications réelles d'opérateurs (confirmation de
  transaction, OTP, solde, forfaits), e-mails de factures ENEO/CAMWATER et
  communications bancaires de routine.

---

## ⚠️ Avertissement éthique

Le fichier `phishing_corpus_synth.csv` est **entièrement synthétique** et destiné
**exclusivement à la recherche défensive** (entraînement et évaluation de
systèmes de détection de phishing).

- Aucune donnée personnelle réelle n'est incluse : les numéros de téléphone sont
  **masqués** (`6XXXXXXXX`), les montants, identifiants et liens sont **fictifs**.
- Les domaines « malveillants » générés sont des exemples **illustratifs** de
  typosquatting et **ne pointent vers aucun service réel**.
- Ces données **ne doivent pas** être utilisées à des fins offensives (envoi
  réel de messages frauduleux, hameçonnage, etc.).

Le petit fichier de référence `phishing_samples_cm.csv` s'inspire de motifs
observés sur le terrain mais ne contient lui non plus aucune donnée personnelle
identifiable (numéros masqués, contenus reformulés).
