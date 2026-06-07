"""Jeux de données de démonstration pour le Bloc 1.

Ces vulnérabilités sont CODÉES EN DUR (réalistes mais fictives quant aux hôtes)
afin de faire tourner le pipeline sans nmap, ZAP ni accès réseau.

⚠️ ÉTHIQUE : ces données sont uniquement à but pédagogique/démonstration.
"""

from __future__ import annotations

from typing import List

from src.common.schemas import Vulnerability


def demo_vulnerabilities() -> List[Vulnerability]:
    """Renvoie un échantillon de :class:`Vulnerability` pour le mode démo.

    La sévérité est laissée à ``None`` : le schéma la dérive du ``cvss_score``.

    Returns:
        Liste de 4 vulnérabilités représentatives (web, réseau, service).
    """
    return [
        Vulnerability(
            id="demo-apache-2449",
            host="10.10.0.21",
            port=80,
            service="http",
            name="Apache HTTP Server Path Traversal & RCE",
            description=(
                "Apache httpd 2.4.49 est vulnérable à une traversée de chemin "
                "permettant la lecture de fichiers hors webroot et, selon la "
                "configuration, l'exécution de code à distance."
            ),
            cve_id="CVE-2021-41773",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            source="nvd",
        ),
        Vulnerability(
            id="demo-ssh-weak",
            host="10.10.0.21",
            port=22,
            service="ssh",
            name="Authentification SSH par mot de passe faible",
            description=(
                "Le service OpenSSH autorise l'authentification par mot de passe "
                "et accepte des identifiants faibles, exposant à des attaques par "
                "force brute."
            ),
            cve_id=None,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            source="nmap",
        ),
        Vulnerability(
            id="demo-xss-reflected",
            host="10.10.0.34",
            port=443,
            service="https",
            name="Cross-Site Scripting (XSS) réfléchi",
            description=(
                "Un paramètre de recherche est renvoyé sans échappement dans la "
                "page, permettant l'injection de scripts côté client."
            ),
            cve_id=None,
            cvss_score=6.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            source="zap",
        ),
        Vulnerability(
            id="demo-tls-info",
            host="10.10.0.34",
            port=443,
            service="https",
            name="En-tête de sécurité HTTP manquant",
            description=(
                "L'en-tête 'Strict-Transport-Security' est absent ; les "
                "connexions peuvent être rétrogradées en HTTP."
            ),
            cve_id=None,
            cvss_score=3.1,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            source="zap",
        ),
    ]
