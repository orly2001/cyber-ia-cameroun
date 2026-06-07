"""Wrapper autour de python-nmap pour la découverte hôtes/ports/services.

⚠️ ÉTHIQUE : ne scannez que des cibles autorisées par écrit.

La dépendance ``python-nmap`` (module ``nmap``) ainsi que le binaire ``nmap``
peuvent être absents de l'environnement. L'import est donc PARESSEUX (effectué
dans la méthode) afin que ce module reste importable partout ; en cas d'absence,
``scan`` journalise l'erreur et renvoie une liste vide.
"""

from __future__ import annotations

from typing import Any, Dict, List

from src.common.logging_conf import get_logger

logger = get_logger(__name__)


class NmapScanner:
    """Encapsule un scan TCP de ports/services via ``python-nmap``."""

    def __init__(self, arguments: str = "-sV -T4") -> None:
        """Initialise le scanner.

        Args:
            arguments: options passées à nmap (``-sV`` = détection de version).
        """
        self.arguments = arguments

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scanne une cible et renvoie les services ouverts détectés.

        Args:
            target: IP ou nom d'hôte (ex. ``"192.168.1.10"``).

        Returns:
            Liste de dicts ``{host, port, protocol, service, product,
            version, state}``. Liste vide si nmap est indisponible ou en erreur.
        """
        try:
            import nmap  # import paresseux : dépendance optionnelle
        except ImportError:
            logger.warning(
                "python-nmap n'est pas installé ; scan nmap ignoré pour %s.", target
            )
            return []

        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=target, arguments=self.arguments)
        except Exception as exc:  # nmap absent du PATH, hôte injoignable, etc.
            logger.error("Échec du scan nmap sur %s : %s", target, exc)
            return []

        results: List[Dict[str, Any]] = []
        for host in scanner.all_hosts():
            host_data = scanner[host]
            for proto in host_data.all_protocols():
                for port in sorted(host_data[proto].keys()):
                    port_info = host_data[proto][port]
                    if port_info.get("state") != "open":
                        continue
                    results.append(
                        {
                            "host": host,
                            "port": int(port),
                            "protocol": proto,
                            "service": port_info.get("name") or None,
                            "product": port_info.get("product") or "",
                            "version": port_info.get("version") or "",
                            "state": port_info.get("state") or "open",
                        }
                    )

        logger.info("nmap : %d service(s) ouvert(s) trouvé(s) sur %s.", len(results), target)
        return results
