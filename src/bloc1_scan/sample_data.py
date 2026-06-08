"""Jeux de données de démonstration pour le Bloc 1.

Ces vulnérabilités sont CODÉES EN DUR (réalistes : vraies CVE, hôtes fictifs)
afin de faire tourner le pipeline et les démos sans nmap, ZAP ni accès réseau.

⚠️ ÉTHIQUE : ces données sont uniquement à but pédagogique/démonstration. Les
hôtes (``10.10.0.x``) sont fictifs ; les CVE référencées, elles, sont réelles.
"""

from __future__ import annotations

from typing import List

from src.common.schemas import Vulnerability


def demo_vulnerabilities() -> List[Vulnerability]:
    """Renvoie un échantillon riche de :class:`Vulnerability` pour le mode démo.

    Couvre les grandes familles OWASP/réseau : RCE (Apache), SQLi, XSS, CSRF,
    désérialisation, et un service SSH faiblement configuré. La sévérité est
    dérivée automatiquement du ``cvss_score`` par le schéma.

    Returns:
        Liste de 6 vulnérabilités représentatives (web + réseau), avec de
        vraies CVE lorsque pertinent, pour des démos crédibles.
    """
    return [
        Vulnerability(
            id="demo-apache-2449",
            host="10.10.0.21",
            port=80,
            service="http",
            name="Apache HTTP Server 2.4.49 — Path Traversal & RCE",
            description=(
                "Apache httpd 2.4.49 est vulnérable à une traversée de chemin "
                "(CVE-2021-41773) permettant la lecture de fichiers hors webroot "
                "et, lorsque mod_cgi est actif, l'exécution de code à distance."
            ),
            cve_id="CVE-2021-41773",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            source="nvd",
        ),
        Vulnerability(
            id="demo-sqli-login",
            host="10.10.0.34",
            port=443,
            service="https",
            name="Injection SQL sur le formulaire d'authentification",
            description=(
                "Le paramètre 'username' du endpoint /login n'est pas paramétré : "
                "une charge ' OR '1'='1 contourne l'authentification et permet "
                "l'extraction de la base utilisateurs (CWE-89)."
            ),
            cve_id=None,
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            source="zap",
        ),
        Vulnerability(
            id="demo-xss-reflected",
            host="10.10.0.34",
            port=443,
            service="https",
            name="Cross-Site Scripting (XSS) réfléchi",
            description=(
                "Le paramètre de recherche 'q' est renvoyé sans échappement dans "
                "la page de résultats, permettant l'injection de scripts côté "
                "client et le vol de session (CWE-79)."
            ),
            cve_id=None,
            cvss_score=6.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            source="zap",
        ),
        Vulnerability(
            id="demo-csrf-transfer",
            host="10.10.0.34",
            port=443,
            service="https",
            name="Cross-Site Request Forgery (CSRF) sur transfert de fonds",
            description=(
                "L'action POST /transfer ne valide aucun jeton anti-CSRF : un site "
                "tiers peut forcer une victime authentifiée à initier un virement "
                "à son insu (CWE-352)."
            ),
            cve_id=None,
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            source="zap",
        ),
        Vulnerability(
            id="demo-log4shell",
            host="10.10.0.50",
            port=8080,
            service="http",
            name="Apache Log4j 2 — RCE via JNDI (Log4Shell)",
            description=(
                "La bibliothèque Log4j 2.x (avant 2.15.0) évalue les recherches "
                "JNDI dans les messages de log (CVE-2021-44228), permettant à un "
                "attaquant d'exécuter du code distant via une chaîne ${jndi:ldap://...}."
            ),
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
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
                "force brute (CWE-307 / CWE-521)."
            ),
            cve_id=None,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            source="nmap",
        ),
    ]


__all__ = ["demo_vulnerabilities"]
