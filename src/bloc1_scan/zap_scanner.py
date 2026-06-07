"""Wrapper OWASP ZAP (via ``zapv2``) pour le scan de vulnérabilités web.

⚠️ ÉTHIQUE : ne lancez un scan actif que sur des applications web dont vous avez
l'autorisation explicite ; un scan actif peut altérer ou perturber le service.

L'import de ``zapv2`` est PARESSEUX. En l'absence du paquet ou si le démon ZAP
n'est pas joignable, ``scan`` journalise et renvoie une liste vide.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from src.common.config import settings
from src.common.logging_conf import get_logger

logger = get_logger(__name__)


class ZapScanner:
    """Encapsule un spider + scan passif OWASP ZAP."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        poll_interval: float = 2.0,
        max_wait: float = 120.0,
    ) -> None:
        """Initialise le client ZAP.

        Args:
            api_url: URL du démon ZAP (défaut : ``settings.zap_api_url``).
            api_key: clé API ZAP (défaut : ``settings.zap_api_key``).
            poll_interval: intervalle (s) entre deux vérifications d'avancement.
            max_wait: durée max (s) d'attente du spider avant abandon.
        """
        self.api_url = api_url or settings.zap_api_url
        self.api_key = api_key or settings.zap_api_key
        self.poll_interval = poll_interval
        self.max_wait = max_wait

    def scan(self, target_url: str) -> List[Dict[str, Any]]:
        """Explore une URL puis récupère les alertes ZAP.

        Args:
            target_url: URL cible (ex. ``"http://exemple.cm"``).

        Returns:
            Liste de dicts ``{host, url, name, description, risk, confidence,
            cveid, reference, solution}``. Liste vide si ZAP est indisponible.
        """
        try:
            from zapv2 import ZAPv2  # import paresseux : dépendance optionnelle
        except ImportError:
            logger.warning(
                "zapv2 n'est pas installé ; scan ZAP ignoré pour %s.", target_url
            )
            return []

        try:
            zap = ZAPv2(
                apikey=self.api_key or None,
                proxies={"http": self.api_url, "https": self.api_url},
            )
            self._spider(zap, target_url)
            alerts = zap.core.alerts(baseurl=target_url)
        except Exception as exc:  # démon ZAP injoignable, erreur réseau, etc.
            logger.error("Échec du scan ZAP sur %s : %s", target_url, exc)
            return []

        results: List[Dict[str, Any]] = []
        for alert in alerts or []:
            url = alert.get("url", "")
            results.append(
                {
                    "host": self._host_from_url(url),
                    "url": url,
                    "name": alert.get("alert") or alert.get("name") or "Alerte ZAP",
                    "description": alert.get("description", ""),
                    "risk": alert.get("risk", ""),
                    "confidence": alert.get("confidence", ""),
                    "cveid": (alert.get("cveid") or "").strip() or None,
                    "reference": alert.get("reference", ""),
                    "solution": alert.get("solution", ""),
                }
            )

        logger.info("ZAP : %d alerte(s) trouvée(s) sur %s.", len(results), target_url)
        return results

    def _spider(self, zap: Any, target_url: str) -> None:
        """Lance le spider ZAP et attend (avec borne) sa complétion."""
        scan_id = zap.spider.scan(target_url)
        elapsed = 0.0
        while elapsed < self.max_wait:
            try:
                progress = int(zap.spider.status(scan_id))
            except (ValueError, TypeError):
                break
            if progress >= 100:
                break
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval
        logger.debug("Spider ZAP terminé pour %s.", target_url)

    @staticmethod
    def _host_from_url(url: str) -> str:
        """Extrait le hostname d'une URL (chaîne vide si invalide)."""
        from urllib.parse import urlparse

        try:
            return urlparse(url).hostname or url
        except Exception:
            return url
