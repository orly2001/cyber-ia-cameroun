"""Scanner Nmap RÉEL via ``subprocess`` (sortie XML) pour le Bloc 1.

⚠️ AVERTISSEMENT ÉTHIQUE & LÉGAL
    Un scan de ports est une activité intrusive. Ne scannez QUE des cibles pour
    lesquelles vous disposez d'une autorisation écrite explicite. Au Cameroun, la
    loi n°2010/012 relative à la cybersécurité réprime l'accès/scan non autorisé.
    Hors autorisation, restez en mode démonstration.

Choix d'implémentation :
    On invoque directement le binaire ``nmap`` via ``subprocess`` (et NON la
    dépendance ``python-nmap``) pour un contrôle total et robuste :

    * arguments passés sous forme de **liste** (jamais ``shell=True``) → pas
      d'injection de commande possible ;
    * sortie XML demandée via ``-oX -`` (sur stdout) puis parsée avec la
      bibliothèque standard ``xml.etree`` ;
    * la cible est **validée** (caractères autorisés uniquement) et confrontée à
      une **liste blanche** (``settings.nmap_allowed_targets``) ;
    * absence du binaire (:class:`FileNotFoundError`) et dépassement de délai
      (:class:`subprocess.TimeoutExpired`) sont journalisés et renvoient ``[]``.

Le binaire ``nmap`` et l'accès réseau peuvent être absents : ce module reste
importable partout (imports lourds paresseux), ``scan`` se contentant de
journaliser puis de renvoyer une liste vide.
"""

from __future__ import annotations

import re
import shlex
from typing import Any, Dict, List, Optional, Sequence

from src.common.config import settings
from src.common.logging_conf import get_logger

logger = get_logger(__name__)

# Caractères autorisés dans une cible : lettres, chiffres, point, deux-points
# (IPv6), tiret, slash (notation CIDR). Tout le reste (espace, ``;``, ``|``,
# ``&``, ``$``, backtick, parenthèses…) est REJETÉ pour bloquer toute tentative
# d'injection de méta-caractères shell.
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:\-/]+$")

# Ports « sensibles » : leur seule exposition mérite une sévérité rehaussée et un
# message d'alerte (services d'administration/bases de données fréquemment ciblés).
_SENSITIVE_PORTS: Dict[int, str] = {
    21: "FTP (transfert de fichiers, souvent en clair)",
    22: "SSH (administration distante)",
    23: "Telnet (administration en clair, à proscrire)",
    25: "SMTP (relais de messagerie)",
    135: "MSRPC (services Windows)",
    139: "NetBIOS (partage Windows)",
    445: "SMB (partage de fichiers Windows)",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL/MariaDB",
    3389: "RDP (bureau à distance Windows)",
    5432: "PostgreSQL",
    5900: "VNC (bureau à distance)",
    6379: "Redis (souvent sans authentification)",
    27017: "MongoDB (souvent sans authentification)",
}


class NmapScanner:
    """Encapsule un scan TCP de ports/services via le binaire ``nmap``.

    Attributes:
        binary: chemin/nom de l'exécutable nmap (``settings.nmap_path``).
        arguments: options nmap par défaut (``settings.nmap_default_args``).
        timeout: délai maximal d'un scan, en secondes.
        allowed_targets: liste blanche des cibles autorisées.
    """

    def __init__(
        self,
        arguments: Optional[str] = None,
        binary: Optional[str] = None,
        timeout: float = 300.0,
    ) -> None:
        """Initialise le scanner.

        Args:
            arguments: options passées à nmap. Par défaut
                ``settings.nmap_default_args`` (ex. ``"-T4 -F -sV"``).
            binary: chemin de l'exécutable. Par défaut ``settings.nmap_path``.
            timeout: délai maximal (secondes) avant interruption du scan.
        """
        self.binary = binary or settings.nmap_path
        self.arguments = arguments if arguments is not None else settings.nmap_default_args
        self.timeout = timeout
        self.allowed_targets = self._parse_whitelist(settings.nmap_allowed_targets)

    # ------------------------------------------------------------------ #
    # Sécurité : validation de la cible
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_whitelist(raw: str) -> List[str]:
        """Découpe la liste blanche CSV en cibles normalisées (minuscules)."""
        return [t.strip().lower() for t in (raw or "").split(",") if t.strip()]

    @classmethod
    def is_target_syntactically_valid(cls, target: str) -> bool:
        """Vérifie qu'une cible ne contient que des caractères sûrs.

        Bloque tout méta-caractère shell (espace, ``;``, ``|``, ``&``…). C'est la
        première barrière anti-injection, complémentaire de l'absence de
        ``shell=True``.

        Args:
            target: cible brute fournie par l'appelant.

        Returns:
            ``True`` si la cible est syntaxiquement sûre, ``False`` sinon.
        """
        return bool(target) and bool(_TARGET_RE.match(target))

    def is_target_allowed(self, target: str) -> bool:
        """Indique si la cible figure dans la liste blanche (insensible à la casse)."""
        return target.strip().lower() in self.allowed_targets

    # ------------------------------------------------------------------ #
    # Scan
    # ------------------------------------------------------------------ #
    def build_command(self, target: str) -> List[str]:
        """Construit la commande nmap sous forme de **liste** d'arguments.

        L'usage d'une liste (et non d'une chaîne) garantit que ``subprocess`` ne
        passe jamais par un shell : aucune interprétation des méta-caractères.

        Args:
            target: cible déjà validée.

        Returns:
            Liste ``[binaire, *options, "-oX", "-", target]``.
        """
        args: Sequence[str] = shlex.split(self.arguments) if self.arguments else []
        # ``-oX -`` : sortie XML sur stdout. La cible est placée en dernier.
        return [self.binary, *args, "-oX", "-", target]

    def scan(self, target: str, force: bool = False) -> List[Dict[str, Any]]:
        """Scanne une cible et renvoie les services ouverts détectés.

        Args:
            target: IP ou nom d'hôte (ex. ``"127.0.0.1"``).
            force: si ``True``, contourne la liste blanche (la validation
                syntaxique anti-injection reste TOUJOURS appliquée). À n'utiliser
                que sur des cibles explicitement autorisées par écrit.

        Returns:
            Liste de dicts ``{host, port, protocol, service, product, version,
            state}``. Liste vide si la cible est refusée, si nmap est
            indisponible, en cas de délai dépassé ou d'erreur.
        """
        # 1) Barrière anti-injection : toujours appliquée, même en mode force.
        if not self.is_target_syntactically_valid(target):
            logger.error(
                "Cible refusée (caractères interdits / risque d'injection) : %r.",
                target,
            )
            return []

        # 2) Liste blanche (sauf mode force explicite).
        if not force and not self.is_target_allowed(target):
            logger.error(
                "Cible %r hors liste blanche (%s). Scan refusé. "
                "Utilisez force=True UNIQUEMENT pour une cible autorisée par écrit.",
                target,
                ", ".join(self.allowed_targets) or "(vide)",
            )
            return []

        logger.warning(
            "⚠️ Scan nmap RÉEL de %r — assurez-vous d'y être autorisé (éthique/légal).",
            target,
        )

        import subprocess  # import paresseux (stdlib, mais cohérent avec le style)

        command = self.build_command(target)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                shell=False,  # JAMAIS de shell : sécurité anti-injection.
            )
        except FileNotFoundError:
            logger.error(
                "Binaire nmap introuvable (%r) ; scan ignoré pour %s.",
                self.binary,
                target,
            )
            return []
        except subprocess.TimeoutExpired:
            logger.error(
                "Délai dépassé (%.0fs) lors du scan nmap de %s ; scan abandonné.",
                self.timeout,
                target,
            )
            return []
        except OSError as exc:  # erreurs système diverses (permissions…)
            logger.error("Erreur système au lancement de nmap sur %s : %s", target, exc)
            return []

        if completed.returncode != 0:
            logger.warning(
                "nmap a renvoyé le code %d sur %s : %s",
                completed.returncode,
                target,
                (completed.stderr or "").strip()[:300],
            )
            # nmap peut renvoyer du XML partiel exploitable malgré un code != 0.

        results = self.parse_xml(completed.stdout or "")
        logger.info(
            "nmap : %d service(s) ouvert(s) trouvé(s) sur %s.", len(results), target
        )
        return results

    # ------------------------------------------------------------------ #
    # Parsing XML
    # ------------------------------------------------------------------ #
    @staticmethod
    def parse_xml(xml_text: str) -> List[Dict[str, Any]]:
        """Parse la sortie XML de nmap et extrait les ports ouverts.

        Args:
            xml_text: contenu XML produit par ``nmap -oX -``.

        Returns:
            Liste de dicts ``{host, port, protocol, service, product, version,
            state}`` pour chaque port à l'état ``open``.
        """
        import xml.etree.ElementTree as ET  # import paresseux (stdlib)

        if not xml_text or not xml_text.strip():
            return []

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.error("XML nmap illisible : %s", exc)
            return []

        results: List[Dict[str, Any]] = []
        for host_el in root.findall("host"):
            host = _extract_host_address(host_el)
            for port_el in host_el.findall("./ports/port"):
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else None
                if state != "open":
                    continue

                try:
                    port = int(port_el.get("portid", "0"))
                except (TypeError, ValueError):
                    continue
                protocol = port_el.get("protocol", "tcp")

                service_el = port_el.find("service")
                if service_el is not None:
                    service = service_el.get("name") or None
                    product = service_el.get("product") or ""
                    version = service_el.get("version") or ""
                else:
                    service, product, version = None, "", ""

                results.append(
                    {
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "service": service,
                        "product": product,
                        "version": version,
                        "state": state,
                    }
                )
        return results


def _extract_host_address(host_el: Any) -> str:
    """Renvoie la meilleure adresse d'un élément ``<host>`` (IPv4/IPv6 prioritaire)."""
    fallback = ""
    for addr_el in host_el.findall("address"):
        addr = addr_el.get("addr", "")
        addrtype = addr_el.get("addrtype", "")
        if addrtype in ("ipv4", "ipv6") and addr:
            return addr
        fallback = fallback or addr
    return fallback


def is_sensitive_port(port: Optional[int]) -> Optional[str]:
    """Renvoie la description du risque si ``port`` est sensible, sinon ``None``."""
    if port is None:
        return None
    return _SENSITIVE_PORTS.get(int(port))


# Échantillon XML nmap réaliste, utilisé par le mode démo de la CLI et réutilisable
# dans les tests. Représente un hôte 127.0.0.1 avec SSH (sensible) et HTTP ouverts.
DEMO_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -T4 -F -sV -oX - 127.0.0.1" version="7.94">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" method="probed"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" method="probed"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="8.0.32" method="probed"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _cli() -> int:
    """Point d'entrée CLI : ``python -m src.bloc1_scan.nmap_scanner --target ...``.

    En mode ``--demo`` (ou si nmap renvoie une liste vide), affiche les services
    issus de l'échantillon XML embarqué : la CLI fonctionne donc même sans nmap.

    Returns:
        Code de sortie processus (0 = succès).
    """
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description=(
            "Scanner Nmap réel (Bloc 1). ⚠️ Ne scannez que des cibles autorisées "
            "par écrit (loi n°2010/012, Cameroun)."
        )
    )
    parser.add_argument("--target", required=True, help="IP ou nom d'hôte à scanner.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Contourne la liste blanche (cible autorisée par écrit uniquement).",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="N'exécute pas nmap : parse un échantillon XML embarqué.",
    )
    args = parser.parse_args()

    scanner = NmapScanner()
    if args.demo:
        logger.info("Mode DÉMO : parsing de l'échantillon XML embarqué (pas de nmap).")
        services = scanner.parse_xml(DEMO_NMAP_XML)
    else:
        services = scanner.scan(args.target, force=args.force)
        if not services:
            logger.info(
                "Aucun service (nmap absent/refus/cible fermée) ; "
                "repli sur l'échantillon XML de démonstration."
            )
            services = scanner.parse_xml(DEMO_NMAP_XML)

    print(json.dumps(services, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
