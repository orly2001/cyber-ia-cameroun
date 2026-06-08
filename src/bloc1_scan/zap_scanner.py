"""Wrapper OWASP ZAP (via ``zapv2``) pour le scan de vulnérabilités web.

⚠️ AVERTISSEMENT ÉTHIQUE & LÉGAL
    Ne lancez un scan (spider + scan actif) que sur des applications web dont
    vous possédez l'AUTORISATION ÉCRITE explicite. Un scan actif envoie des
    charges potentiellement destructrices (injections, fuzzing) et peut altérer
    ou perturber le service cible. Scanner un système tiers sans accord est
    illégal au Cameroun (loi n°2010/012 sur la cybersécurité) comme ailleurs.

Architecture :
    Le démon ZAP agit comme un proxy HTTP local exposant une API REST. Le client
    ``zapv2`` (paquet ``python-owasp-zap-v2.4``) pilote ce démon. L'import est
    PARESSEUX : en l'absence du paquet ou si le démon est injoignable, ``scan``
    journalise un message clair et renvoie ``[]`` (jamais d'exception remontée).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.common.config import settings
from src.common.logging_conf import get_logger

logger = get_logger(__name__)


class ZapScanner:
    """Pilote un flux OWASP ZAP complet : accès → spider → scan actif → alertes."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        poll_interval: float = 2.0,
        max_wait: float = 180.0,
        active_scan: bool = True,
    ) -> None:
        """Initialise le client ZAP.

        Args:
            api_url: URL du démon ZAP servant aussi de proxy
                (défaut : ``settings.zap_api_url``).
            api_key: clé API ZAP (défaut : ``settings.zap_api_key``).
            poll_interval: intervalle (s) entre deux vérifications d'avancement.
            max_wait: durée max (s) d'attente de CHAQUE phase (spider, scan
                actif) avant abandon de la phase concernée.
            active_scan: si ``False``, on s'arrête après le spider (scan passif
                uniquement) — utile pour une démo rapide et moins intrusive.
        """
        self.api_url = api_url or settings.zap_api_url
        self.api_key = api_key or settings.zap_api_key
        self.poll_interval = poll_interval
        self.max_wait = max_wait
        self.active_scan = active_scan

    # ------------------------------------------------------------------ #
    # API publique
    # ------------------------------------------------------------------ #
    def scan(self, target_url: str) -> List[Dict[str, Any]]:
        """Exécute le flux ZAP complet et renvoie les alertes normalisées.

        Flux : ``zap.urlopen`` (amorce le site) → spider (poll jusqu'à 100 %)
        → scan actif optionnel (poll jusqu'à 100 %) → ``zap.core.alerts``.

        Args:
            target_url: URL cible (ex. ``"http://localhost:8080"``).

        Returns:
            Liste de dicts riches ``{host, url, name, risk, param, method,
            cweid, description, solution, reference, confidence}``. Liste vide
            si ``zapv2`` est absent ou si le démon ZAP est injoignable.
        """
        zap = self._connect()
        if zap is None:
            return []

        try:
            self._open_url(zap, target_url)
            self._spider(zap, target_url)
            if self.active_scan:
                self._active_scan(zap, target_url)
            alerts = zap.core.alerts(baseurl=target_url)
        except Exception as exc:  # noqa: BLE001 — démon injoignable, réseau, etc.
            logger.error("Échec du scan ZAP sur %s : %s", target_url, exc)
            return []

        results = [self._map_alert(alert) for alert in (alerts or [])]
        logger.info("ZAP : %d alerte(s) trouvée(s) sur %s.", len(results), target_url)
        return results

    # ------------------------------------------------------------------ #
    # Connexion / phases
    # ------------------------------------------------------------------ #
    def _connect(self) -> Optional[Any]:
        """Instancie le client ``zapv2`` (import paresseux). ``None`` si indispo."""
        try:
            from zapv2 import ZAPv2  # import paresseux : dépendance optionnelle
        except ImportError:
            logger.warning(
                "zapv2 n'est pas installé (pip install python-owasp-zap-v2.4) ; "
                "scan ZAP ignoré."
            )
            return None

        try:
            return ZAPv2(
                apikey=self.api_key or None,
                proxies={"http": self.api_url, "https": self.api_url},
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Impossible d'initialiser le client ZAP (%s) : %s",
                         self.api_url, exc)
            return None

    def _open_url(self, zap: Any, target_url: str) -> None:
        """Demande à ZAP de charger l'URL cible (alimente l'arbre des sites)."""
        zap.urlopen(target_url)
        # Laisse au démon le temps d'enregistrer la requête passive.
        time.sleep(min(self.poll_interval, 2.0))
        logger.debug("ZAP a ouvert l'URL %s.", target_url)

    def _spider(self, zap: Any, target_url: str) -> None:
        """Lance le spider et attend (avec borne) sa complétion (100 %)."""
        scan_id = zap.spider.scan(target_url)
        logger.info("Spider ZAP démarré (id=%s) sur %s.", scan_id, target_url)
        self._poll(lambda: zap.spider.status(scan_id), "spider", target_url)
        logger.info("Spider ZAP terminé pour %s.", target_url)

    def _active_scan(self, zap: Any, target_url: str) -> None:
        """Lance le scan actif (ascan) et attend (avec borne) sa complétion."""
        scan_id = zap.ascan.scan(target_url)
        logger.info("Scan actif ZAP démarré (id=%s) sur %s.", scan_id, target_url)
        self._poll(lambda: zap.ascan.status(scan_id), "scan actif", target_url)
        logger.info("Scan actif ZAP terminé pour %s.", target_url)

    def _poll(self, status_fn: Any, phase: str, target_url: str) -> None:
        """Interroge ``status_fn`` jusqu'à 100 % ou expiration de ``max_wait``.

        Args:
            status_fn: callable renvoyant l'avancement (0-100, str ou int).
            phase: libellé de la phase (journalisation).
            target_url: cible (journalisation).
        """
        elapsed = 0.0
        while elapsed < self.max_wait:
            try:
                progress = int(status_fn())
            except (ValueError, TypeError):
                # Certaines erreurs ZAP renvoient un statut non numérique : on
                # considère la phase comme terminée pour ne pas boucler.
                logger.debug("Statut %s non numérique ; phase considérée finie.", phase)
                return
            if progress >= 100:
                return
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval
        logger.warning(
            "Timeout (%.0fs) sur la phase « %s » pour %s ; on poursuit.",
            self.max_wait, phase, target_url,
        )

    # ------------------------------------------------------------------ #
    # Mapping & utilitaires
    # ------------------------------------------------------------------ #
    def _map_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise une alerte ZAP brute en dict riche et stable."""
        url = alert.get("url", "") or ""
        cweid = (str(alert.get("cweid", "")) or "").strip() or None
        return {
            "host": self._host_from_url(url),
            "url": url,
            "name": alert.get("alert") or alert.get("name") or "Alerte ZAP",
            "risk": alert.get("risk", "") or "",
            "param": alert.get("param", "") or "",
            "method": alert.get("method", "") or "",
            "cweid": cweid,
            "cveid": (str(alert.get("cveid", "")) or "").strip() or None,
            "description": alert.get("description", "") or "",
            "solution": alert.get("solution", "") or "",
            "reference": alert.get("reference", "") or "",
            "confidence": alert.get("confidence", "") or "",
        }

    @staticmethod
    def _host_from_url(url: str) -> str:
        """Extrait le hostname d'une URL (chaîne d'origine si invalide)."""
        try:
            return urlparse(url).hostname or url
        except Exception:  # noqa: BLE001
            return url
