"""Générateur synthétique CONTRÔLÉ de corpus de phishing camerounais.

⚠️ AVERTISSEMENT ÉTHIQUE
------------------------
Ce module produit des messages ENTIÈREMENT SYNTHÉTIQUES destinés exclusivement
à la **recherche défensive** (entraînement/évaluation de détecteurs de phishing).
Aucune donnée personnelle réelle n'est utilisée : tous les numéros, montants,
identifiants et liens sont fictifs ou masqués. Les domaines « malveillants »
générés sont des exemples typosquattés illustratifs et ne pointent vers aucun
service réel. Ne pas utiliser ce générateur à des fins offensives.

Le corpus reflète le contexte camerounais :

* SMS frauduleux Mobile Money (MTN MoMo / Orange Money) : compte suspendu,
  gain loterie, demande de code PIN, faux transfert reçu ;
* e-mails de phishing bancaires (Afriland, UBA, Ecobank, BICEC) et faux
  services ;
* URLs malveillantes (typosquatting .ml/.tk/.cm-secure, raccourcisseurs) ;
* messages LÉGITIMES : notifications réelles d'opérateurs (confirmation de
  transaction, OTP, solde, forfaits) et e-mails ENEO/CAMWATER (factures).

Conformité stricte au contrat :class:`src.common.schemas.PhishingSample`.

``pandas``/``numpy`` ne sont PAS importés au niveau module ; aucun import
externe lourd n'est requis (le générateur n'utilise que la bibliothèque
standard). L'export CSV respecte le format du corpus existant
(``id, channel, raw_text, language, label, source``) en s'appuyant sur le
module ``csv`` pour échapper correctement virgules et guillemets.
"""

from __future__ import annotations

import csv
import random
from pathlib import Path
from typing import Callable, List, Optional, Union

from src.common.logging_conf import get_logger
from src.common.schemas import Channel, PhishingSample

logger = get_logger(__name__)

SYNTHETIC_SOURCE = "synthetic"

# --------------------------------------------------------------------------- #
# Briques de variabilité (toutes fictives / masquées)
# --------------------------------------------------------------------------- #

#: Opérateurs Mobile Money camerounais.
_MOMO_OPERATORS = [
    ("MTN MoMo", "MTN Mobile Money", "MTN"),
    ("Orange Money", "Orange Money", "Orange"),
]

#: Banques camerounaises (légitimes ; usurpées dans les exemples de phishing).
_BANKS = ["Afriland First Bank", "UBA", "Ecobank", "BICEC", "SGBC", "CCA Bank"]

#: Opérateurs télécom / utilities.
_TELCOS = ["MTN", "Orange", "CAMTEL", "Nexttel"]
_UTILITIES = [("ENEO", "facture d'electricite"), ("CAMWATER", "facture d'eau")]

#: Domaines typosquattés / suspects (TLD bon marché souvent abusés). Fictifs.
_PHISH_DOMAINS = [
    "momo-verify.cm-secure.net",
    "mtn-momo-securise.ml",
    "orange-money-confirm.tk",
    "afriland-secure-login.com",
    "uba-cameroun.account-verify.ml",
    "ecobank-cm-login.tk",
    "bicec-online.cm-secure.net",
    "secure-banking-cm.ml",
    "verify-account-cm.tk",
    "momo-bonus-cm.ml",
]

#: Raccourcisseurs (les liens sont fictifs).
_SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co"]

#: Domaines légitimes (sites institutionnels réels, utilisés en label=0).
_LEGIT_DOMAINS = [
    "www.ecobank.com/cm/personal-banking",
    "www.ubagroup.com/cm/",
    "www.afrilandfirstbank.com",
    "www.bicec.com",
    "www.eneo.cm/espace-client",
    "www.camwater.cm",
    "www.mtn.cm/momo",
    "www.orange.cm/orange-money",
]


def _rand_token(rng: random.Random, n: int = 6) -> str:
    """Petit jeton alphanumérique aléatoire (chemins de liens fictifs)."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(n))


def _masked_phone(rng: random.Random) -> str:
    """Numéro camerounais partiellement masqué (jamais un vrai numéro).

    Format ``6XXXXXXXX`` avec la majorité des chiffres remplacés par ``X``.
    """
    prefix = rng.choice(["6", "69", "65", "67", "68"])
    visible = "".join(str(rng.randint(0, 9)) for _ in range(rng.randint(0, 1)))
    return prefix + visible + "X" * (9 - len(prefix) - len(visible))


def _amount_fcfa(rng: random.Random) -> int:
    """Montant FCFA réaliste (multiples « ronds » fréquents en Mobile Money)."""
    bucket = rng.random()
    if bucket < 0.45:  # petits transferts du quotidien
        return rng.choice([500, 1000, 2000, 2500, 5000, 7500, 10000])
    if bucket < 0.8:  # transferts moyens
        return rng.choice([15000, 20000, 25000, 30000, 50000, 75000])
    # gros montants (souvent dans les arnaques « loterie »)
    return rng.choice([100000, 250000, 500000, 1000000, 2000000, 5000000])


def _fmt_amount(rng: random.Random, amount: int) -> str:
    """Formate un montant FCFA avec une variabilité de séparateurs réaliste."""
    style = rng.random()
    if style < 0.5:
        return f"{amount}"
    if style < 0.8:
        return f"{amount:,}".replace(",", " ")
    return f"{amount:,}".replace(",", ".")


def _phish_link(rng: random.Random) -> str:
    """Construit un lien malveillant fictif (domaine suspect ou raccourcisseur)."""
    if rng.random() < 0.55:
        scheme = rng.choice(["http://", "https://", ""])
        domain = rng.choice(_PHISH_DOMAINS)
        path = rng.choice(["", "/login", "/verify", "/confirm", f"/{_rand_token(rng)}"])
        return f"{scheme}{domain}{path}"
    shortener = rng.choice(_SHORTENERS)
    return f"{shortener}/{_rand_token(rng)}"


def _legit_link(rng: random.Random) -> str:
    """Lien légitime (site institutionnel réel)."""
    scheme = rng.choice(["https://", ""])
    return f"{scheme}{rng.choice(_LEGIT_DOMAINS)}"


def _add_sms_noise(rng: random.Random, text: str) -> str:
    """Ajoute des artefacts SMS réalistes (ponctuation, fautes, casse).

    On reste léger pour préserver la lisibilité tout en simulant le bruit
    typique des SMS frauduleux (urgence, exclamations multiples, accents omis).
    """
    # Urgence : exclamations / majuscules occasionnelles.
    if rng.random() < 0.3:
        text = text.replace(".", "!")
    if rng.random() < 0.2:
        text = text + rng.choice([" URGENT", " Repondez vite", " Action requise"])
    if rng.random() < 0.15:
        text = text + "!!"
    # Fautes/abréviations SMS fréquentes (sur copie, sans données réelles).
    if rng.random() < 0.25:
        text = text.replace("votre", "vtre").replace("vous", "vs")
    return text


# --------------------------------------------------------------------------- #
# Templates — chaque fonction renvoie (raw_text, channel, language)
# --------------------------------------------------------------------------- #

def _t_phish_sms_suspended(rng: random.Random):
    op_full, op_long, _ = rng.choice(_MOMO_OPERATORS)
    link = _phish_link(rng)
    fr = [
        f"Cher client {op_full}, votre compte sera suspendu sous 24h. "
        f"Confirmez votre code PIN ici: {link}",
        f"{op_full}: activite suspecte detectee. Verifiez votre identite "
        f"immediatement: {link}",
        f"AVIS {op_long}: votre compte est bloque. Reactivez-le maintenant: {link}",
        f"{op_full} Securite: validez votre code secret pour eviter la "
        f"suspension: {link}",
    ]
    en = [
        f"Dear {op_full} customer, your account will be suspended. "
        f"Confirm your PIN here: {link}",
        f"{op_full}: suspicious activity. Verify your identity now: {link}",
    ]
    lang, pool = ("en", en) if rng.random() < 0.2 else ("fr", fr)
    return _add_sms_noise(rng, rng.choice(pool)), Channel.SMS, lang


def _t_phish_sms_lottery(rng: random.Random):
    op_full, op_long, op_brand = rng.choice(_MOMO_OPERATORS)
    amount = rng.choice([1000000, 2000000, 5000000, 500000, 10000000])
    amt = _fmt_amount(rng, amount)
    phone = _masked_phone(rng)
    fr = [
        f"Felicitations! Vous avez gagne {amt} FCFA a la loterie {op_brand}. "
        f"Envoyez vos infos au {phone}",
        f"GAGNANT {op_brand}! Votre numero a remporte {amt} FCFA. "
        f"Contactez le {phone} pour reclamer.",
        f"Bonne nouvelle: tirage {op_full} - vous gagnez {amt} FCFA. "
        f"Appelez {phone} maintenant.",
        f"Promo {op_brand} 2026: vous etes selectionne pour {amt} FCFA. "
        f"Repondez avec votre nom au {phone}.",
    ]
    en = [
        f"Congratulations! You won {amt} FCFA in the {op_brand} lottery. "
        f"Send your details to {phone}",
        f"WINNER {op_brand}! Claim your {amt} FCFA prize. Call {phone} now.",
    ]
    lang, pool = ("en", en) if rng.random() < 0.2 else ("fr", fr)
    return _add_sms_noise(rng, rng.choice(pool)), Channel.SMS, lang


def _t_phish_sms_pin(rng: random.Random):
    op_full, _, _ = rng.choice(_MOMO_OPERATORS)
    code = "".join(str(rng.randint(0, 9)) for _ in range(rng.choice([4, 5, 6])))
    fr = [
        f"{op_full}: pour finaliser l'operation, communiquez le code {code} "
        f"recu par SMS a notre agent.",
        f"Service {op_full}: envoyez votre code PIN et le code {code} pour "
        f"debloquer votre compte.",
        f"{op_full} Verification: donnez-nous votre mot de passe et le code "
        f"{code} pour securiser votre compte.",
    ]
    en = [
        f"{op_full}: to complete the transaction, share the code {code} with "
        f"our agent.",
    ]
    lang, pool = ("en", en) if rng.random() < 0.15 else ("fr", fr)
    return _add_sms_noise(rng, rng.choice(pool)), Channel.SMS, lang


def _t_phish_sms_fake_transfer(rng: random.Random):
    op_full, _, _ = rng.choice(_MOMO_OPERATORS)
    amount = _amount_fcfa(rng)
    amt = _fmt_amount(rng, amount)
    link = _phish_link(rng)
    fr = [
        f"{op_full}: vous avez recu {amt} FCFA. Cliquez pour valider la "
        f"reception: {link}",
        f"Transfert recu de {amt} FCFA via {op_full}. Confirmez ici: {link}",
        f"{op_full}: un envoi de {amt} FCFA est en attente. Validez sous 1h: "
        f"{link}",
    ]
    en = [
        f"{op_full}: you received {amt} FCFA. Click to validate: {link}",
    ]
    lang, pool = ("en", en) if rng.random() < 0.15 else ("fr", fr)
    return _add_sms_noise(rng, rng.choice(pool)), Channel.SMS, lang


def _t_phish_email_bank(rng: random.Random):
    bank = rng.choice(_BANKS)
    link = _phish_link(rng)
    fr = [
        f"Cher client, votre compte {bank} est verrouille pour raison de "
        f"securite. Verifiez vos identifiants ici: {link}",
        f"{bank} - Service en ligne: une connexion inhabituelle a ete "
        f"detectee. Reactivez votre acces: {link}",
        f"Important: votre carte {bank} sera desactivee. Mettez a jour vos "
        f"informations: {link}",
        f"{bank}: votre session bancaire a expire. Reconnectez-vous "
        f"immediatement via {link} pour eviter la fermeture du compte.",
    ]
    en = [
        f"Dear customer, your {bank} account is locked. Verify now: {link}",
        f"{bank} Online: unusual login detected. Restore access: {link}",
        f"Important: your {bank} card will be deactivated. Update your details: {link}",
    ]
    lang, pool = ("en", en) if rng.random() < 0.35 else ("fr", fr)
    return rng.choice(pool), Channel.EMAIL, lang


def _t_phish_email_service(rng: random.Random):
    link = _phish_link(rng)
    fr = [
        f"Votre colis n'a pas pu etre livre. Reglez les frais de douane ici: {link}",
        f"Service client: votre abonnement a expire. Renouvelez maintenant: {link}",
        f"Vous avez 1 message vocal en attente. Ecoutez-le ici: {link}",
        f"Mise a jour requise de votre profil pour eviter la suspension: {link}",
    ]
    en = [
        f"Your parcel could not be delivered. Pay customs fees here: {link}",
        f"Your subscription has expired. Renew now: {link}",
    ]
    lang, pool = ("en", en) if rng.random() < 0.3 else ("fr", fr)
    return rng.choice(pool), Channel.EMAIL, lang


def _t_phish_url(rng: random.Random):
    link = _phish_link(rng)
    if not link.startswith("http"):
        link = "http://" + link
    # Les URLs sont majoritairement annotees 'en' dans le CSV existant.
    lang = "en" if rng.random() < 0.7 else "fr"
    return link, Channel.URL, lang


def _t_legit_sms_transaction(rng: random.Random):
    op_full, _, _ = rng.choice(_MOMO_OPERATORS)
    amount = _amount_fcfa(rng)
    bal = amount + rng.randint(500, 80000)
    phone = _masked_phone(rng)
    amt, bal_s = _fmt_amount(rng, amount), _fmt_amount(rng, bal)
    fr = [
        f"Votre transfert {op_full} de {amt} FCFA vers {phone} a reussi. "
        f"Solde: {bal_s} FCFA.",
        f"{op_full}: paiement de {amt} FCFA effectue. Nouveau solde: {bal_s} FCFA. "
        f"Frais: 0 FCFA.",
        f"{op_full}: vous avez recu {amt} FCFA de {phone}. Solde disponible: "
        f"{bal_s} FCFA.",
        f"Retrait {op_full} de {amt} FCFA reussi. Solde: {bal_s} FCFA. "
        f"Merci de votre confiance.",
    ]
    en = [
        f"Your {op_full} transfer of {amt} FCFA to {phone} succeeded. "
        f"Balance: {bal_s} FCFA.",
    ]
    lang, pool = ("en", en) if rng.random() < 0.15 else ("fr", fr)
    return rng.choice(pool), Channel.SMS, lang


def _t_legit_sms_otp(rng: random.Random):
    op_full, _, _ = rng.choice(_MOMO_OPERATORS)
    code = "".join(str(rng.randint(0, 9)) for _ in range(rng.choice([4, 6])))
    fr = [
        f"{op_full}: votre code de validation est {code}. Ne le partagez avec "
        f"personne.",
        f"Votre code OTP {op_full} est {code}. Valable 5 minutes. Ne le "
        f"communiquez a personne.",
        f"{op_full}: {code} est votre code de securite. Notre service ne vous "
        f"le demandera jamais.",
    ]
    en = [
        f"{op_full}: your verification code is {code}. Do not share it.",
        f"Your {op_full} OTP is {code}. Valid for 5 minutes.",
    ]
    lang, pool = ("en", en) if rng.random() < 0.2 else ("fr", fr)
    return rng.choice(pool), Channel.SMS, lang


def _t_legit_sms_balance_bundle(rng: random.Random):
    telco = rng.choice(_TELCOS)
    go = rng.choice([1, 2, 5, 10, 15, 30])
    days = rng.choice([1, 7, 30])
    price = rng.choice([500, 1000, 2000, 5000])
    bal = _fmt_amount(rng, rng.randint(50, 50000))
    fr = [
        f"{telco}: votre forfait internet de {go}Go est active pour {days} "
        f"jours. Merci.",
        f"{telco}: rechargez {price}F et recevez {go}Go. Composez *123#. Offre "
        f"valable aujourd'hui.",
        f"{telco}: votre solde credit est de {bal} FCFA. Rechargez via *155#.",
        f"{telco}: il vous reste {go}Go de data valables {days} jours. Bonne "
        f"navigation.",
    ]
    en = [
        f"{telco}: your {go}GB internet bundle is active for {days} days. Thank you.",
    ]
    lang, pool = ("en", en) if rng.random() < 0.15 else ("fr", fr)
    return rng.choice(pool), Channel.SMS, lang


def _t_legit_email_utility(rng: random.Random):
    util, label = rng.choice(_UTILITIES)
    amount = _fmt_amount(rng, rng.choice([3500, 5200, 8400, 12500, 18900, 24300]))
    month = rng.choice([
        "janvier", "fevrier", "mars", "avril", "mai", "juin",
        "juillet", "aout", "septembre", "octobre", "novembre", "decembre",
    ])
    fr = [
        f"Votre {label} {util} du mois de {month} est disponible dans votre "
        f"espace client. Montant: {amount} FCFA. Cordialement.",
        f"{util}: votre {label} de {month} s'eleve a {amount} FCFA. Consultez "
        f"votre espace abonne pour le detail.",
        f"Bonjour, votre {label} {util} ({month}) est prete. Vous pouvez la "
        f"regler en agence ou via Mobile Money. Merci.",
    ]
    en = [
        f"Your {util} bill for {month} is available in your customer area. "
        f"Amount: {amount} FCFA.",
    ]
    lang, pool = ("en", en) if rng.random() < 0.1 else ("fr", fr)
    return rng.choice(pool), Channel.EMAIL, lang


def _t_legit_email_bank(rng: random.Random):
    bank = rng.choice(_BANKS)
    fr = [
        f"{bank}: votre releve de compte mensuel est disponible dans votre "
        f"espace client securise. Cordialement, le service clientele.",
        f"Cher client, {bank} vous informe de la mise a jour de vos conditions "
        f"tarifaires. Consultez votre agence pour plus d'informations.",
        f"{bank}: nous vous remercions pour votre fidelite. Aucune action "
        f"n'est requise de votre part.",
    ]
    en = [
        f"{bank}: your monthly statement is available in your secure customer "
        f"area. Best regards, customer service.",
    ]
    lang, pool = ("en", en) if rng.random() < 0.2 else ("fr", fr)
    return rng.choice(pool), Channel.EMAIL, lang


def _t_legit_url(rng: random.Random):
    link = _legit_link(rng)
    if not link.startswith("http"):
        link = "https://" + link
    lang = "en" if rng.random() < 0.7 else "fr"
    return link, Channel.URL, lang


# Pondération des générateurs par classe (diversité des canaux/scénarios).
_PHISH_TEMPLATES: List[Callable] = [
    _t_phish_sms_suspended,
    _t_phish_sms_lottery,
    _t_phish_sms_pin,
    _t_phish_sms_fake_transfer,
    _t_phish_email_bank,
    _t_phish_email_service,
    _t_phish_url,
]

_LEGIT_TEMPLATES: List[Callable] = [
    _t_legit_sms_transaction,
    _t_legit_sms_otp,
    _t_legit_sms_balance_bundle,
    _t_legit_email_utility,
    _t_legit_email_bank,
    _t_legit_url,
]


# --------------------------------------------------------------------------- #
# API publique
# --------------------------------------------------------------------------- #

def _generate_class(
    rng: random.Random,
    templates: List[Callable],
    n: int,
    label: int,
    start_index: int,
    max_attempts_factor: int = 50,
) -> List[PhishingSample]:
    """Génère ``n`` échantillons d'une classe en évitant les doublons exacts."""
    samples: List[PhishingSample] = []
    seen: set = set()
    idx = start_index
    attempts = 0
    max_attempts = n * max_attempts_factor
    while len(samples) < n and attempts < max_attempts:
        attempts += 1
        template = rng.choice(templates)
        raw_text, channel, language = template(rng)
        raw_text = raw_text.strip()
        if not raw_text or raw_text in seen:
            continue
        seen.add(raw_text)
        samples.append(
            PhishingSample(
                id=f"gen-{idx:04d}",
                channel=channel,
                raw_text=raw_text,
                clean_text=None,
                language=language,
                label=label,
                source=SYNTHETIC_SOURCE,
            )
        )
        idx += 1
    if len(samples) < n:
        logger.warning(
            "Seulement %d/%d échantillons uniques générés pour label=%d "
            "(diversité des templates atteinte).",
            len(samples),
            n,
            label,
        )
    return samples


def generate_corpus(n_per_class: int = 120, seed: int = 42) -> List[PhishingSample]:
    """Génère un corpus synthétique équilibré phishing/légitime.

    Args:
        n_per_class: nombre d'échantillons par classe (phishing puis légitime).
        seed: graine pour la reproductibilité.

    Returns:
        Liste de :class:`PhishingSample` (taille ≈ ``2 * n_per_class``) avec des
        identifiants uniques ``gen-XXXX``, ``label`` 0/1, ``source='synthetic'``,
        multilingue (français majoritaire + anglais). Aucune donnée réelle.
    """
    rng = random.Random(seed)

    phishing = _generate_class(rng, _PHISH_TEMPLATES, n_per_class, label=1, start_index=1)
    legit = _generate_class(
        rng, _LEGIT_TEMPLATES, n_per_class, label=0, start_index=n_per_class + 1
    )

    samples = phishing + legit
    rng.shuffle(samples)  # mélange phishing/légitime
    logger.info(
        "Corpus synthétique généré : %d échantillons (%d phishing / %d légitimes).",
        len(samples),
        len(phishing),
        len(legit),
    )
    return samples


def export_csv(samples: List[PhishingSample], path: Union[str, Path]) -> Path:
    """Exporte les échantillons au format CSV du corpus existant.

    Colonnes : ``id, channel, raw_text, language, label, source``. Les virgules
    et guillemets contenus dans ``raw_text`` sont correctement échappés via le
    module ``csv`` (QUOTE_MINIMAL). Contrairement au CSV livré manuellement (qui
    aligne les colonnes avec des espaces), cet export n'ajoute pas de padding :
    le loader (``skipinitialspace=True`` + ``strip``) lit indifféremment les
    deux formats.

    Args:
        samples: échantillons à écrire.
        path: chemin du fichier CSV de sortie (le dossier parent est créé).

    Returns:
        Le chemin du fichier écrit.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["id", "channel", "raw_text", "language", "label", "source"])
        for s in samples:
            label = "" if s.label is None else str(s.label)
            writer.writerow(
                [
                    s.id,
                    s.channel.value,
                    s.raw_text,
                    s.language,
                    label,
                    s.source,
                ]
            )

    logger.info("%d échantillon(s) exporté(s) vers %s.", len(samples), out)
    return out


__all__ = ["generate_corpus", "export_csv", "SYNTHETIC_SOURCE"]
