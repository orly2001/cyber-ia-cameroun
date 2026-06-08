"""Tests du scanner Nmap réel (Bloc 1) — sans nmap ni réseau.

Stratégie : on MOCKE ``subprocess.run`` pour renvoyer un XML nmap réaliste, puis
on vérifie le parsing, le mapping vers :class:`Vulnerability`, la sécurité
(liste blanche + anti-injection) et la robustesse (binaire absent, timeout).
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from src.bloc1_scan.nmap_scanner import (
    DEMO_NMAP_XML,
    NmapScanner,
    is_sensitive_port,
)
from src.bloc1_scan.scanner import _nmap_service_to_vuln
from src.common.schemas import Severity, Vulnerability

# Échantillon XML nmap réaliste : 127.0.0.1 avec SSH, HTTP, MySQL ouverts et un
# port fermé (qui doit être ignoré par le parseur).
SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -T4 -F -sV -oX - 127.0.0.1" version="7.94">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" method="probed"/>
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


def _fake_completed(stdout: str, returncode: int = 0):
    """Fabrique un faux objet CompletedProcess minimal."""
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)


# --------------------------------------------------------------------------- #
# Parsing XML
# --------------------------------------------------------------------------- #
def test_parse_xml_extrait_ports_ouverts():
    services = NmapScanner.parse_xml(SAMPLE_XML)
    # 3 ports ouverts (le port 9999 fermé est ignoré).
    assert len(services) == 3
    ports = {s["port"] for s in services}
    assert ports == {22, 80, 3306}

    ssh = next(s for s in services if s["port"] == 22)
    assert ssh["host"] == "127.0.0.1"
    assert ssh["protocol"] == "tcp"
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.2p1"
    assert ssh["state"] == "open"


def test_parse_xml_vide_renvoie_liste():
    assert NmapScanner.parse_xml("") == []
    assert NmapScanner.parse_xml("   ") == []


def test_parse_xml_malforme_renvoie_liste():
    assert NmapScanner.parse_xml("<nmaprun><host>") == []


# --------------------------------------------------------------------------- #
# scan() avec subprocess.run mocké
# --------------------------------------------------------------------------- #
def test_scan_avec_subprocess_mocke(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _fake_completed(SAMPLE_XML)

    monkeypatch.setattr(subprocess, "run", fake_run)

    scanner = NmapScanner()
    services = scanner.scan("127.0.0.1")  # cible de la liste blanche

    assert len(services) == 3
    # Sécurité : jamais de shell=True ; commande passée en LISTE.
    assert isinstance(captured["cmd"], list)
    assert captured["kwargs"].get("shell") in (False, None)
    # La sortie XML doit être demandée sur stdout.
    assert "-oX" in captured["cmd"]
    assert "-" in captured["cmd"]
    # La cible figure dans la commande (en dernier).
    assert captured["cmd"][-1] == "127.0.0.1"


# --------------------------------------------------------------------------- #
# Mapping -> Vulnerability
# --------------------------------------------------------------------------- #
def test_mapping_vers_vulnerability_conforme(monkeypatch):
    # Évite tout appel réseau d'enrichissement NVD.
    monkeypatch.setattr(
        "src.bloc1_scan.scanner.enrich_with_nvd", lambda *a, **k: []
    )
    services = NmapScanner.parse_xml(SAMPLE_XML)
    vulns = [_nmap_service_to_vuln(s) for s in services]

    assert all(isinstance(v, Vulnerability) for v in vulns)

    ssh_svc = next(s for s in services if s["port"] == 22)
    ssh_vuln = _nmap_service_to_vuln(ssh_svc)
    assert ssh_vuln.source == "nmap"
    assert ssh_vuln.host == "127.0.0.1"
    assert ssh_vuln.port == 22
    assert ssh_vuln.service == "ssh"
    # Libellé "Port 22/tcp ouvert (ssh OpenSSH 8.2p1)".
    assert "Port 22/tcp ouvert" in ssh_vuln.name
    assert "ssh" in ssh_vuln.name
    assert "OpenSSH" in ssh_vuln.name
    # Identifiant stable et non vide.
    assert ssh_vuln.id and ssh_vuln.id == _nmap_service_to_vuln(ssh_svc).id


def test_port_sensible_eleve_la_severite(monkeypatch):
    monkeypatch.setattr(
        "src.bloc1_scan.scanner.enrich_with_nvd", lambda *a, **k: []
    )
    services = NmapScanner.parse_xml(SAMPLE_XML)

    ssh = _nmap_service_to_vuln(next(s for s in services if s["port"] == 22))
    mysql = _nmap_service_to_vuln(next(s for s in services if s["port"] == 3306))
    http = _nmap_service_to_vuln(next(s for s in services if s["port"] == 80))

    # Ports sensibles (22 SSH, 3306 MySQL) -> MEDIUM avec message.
    assert ssh.severity == Severity.MEDIUM
    assert mysql.severity == Severity.MEDIUM
    assert "sensible" in ssh.description.lower()
    # Port 80 non sensible -> INFO.
    assert http.severity == Severity.INFO


def test_is_sensitive_port():
    assert is_sensitive_port(22)
    assert is_sensitive_port(3306)
    assert is_sensitive_port(3389)
    assert is_sensitive_port(80) is None
    assert is_sensitive_port(None) is None


# --------------------------------------------------------------------------- #
# Sécurité : liste blanche
# --------------------------------------------------------------------------- #
def test_cible_hors_whitelist_refusee(monkeypatch):
    appele = {"run": False}

    def fake_run(*a, **k):  # ne doit JAMAIS être appelé
        appele["run"] = True
        return _fake_completed(SAMPLE_XML)

    monkeypatch.setattr(subprocess, "run", fake_run)

    scanner = NmapScanner()
    # 8.8.8.8 n'est pas dans la liste blanche par défaut.
    assert scanner.scan("8.8.8.8") == []
    assert appele["run"] is False


def test_force_contourne_la_whitelist(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _fake_completed(SAMPLE_XML))
    scanner = NmapScanner()
    # Hors whitelist mais force=True -> scan effectué.
    services = scanner.scan("8.8.8.8", force=True)
    assert len(services) == 3


# --------------------------------------------------------------------------- #
# Sécurité : anti-injection
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "mauvaise_cible",
    [
        "127.0.0.1; rm -rf /",
        "127.0.0.1 && whoami",
        "127.0.0.1 | cat /etc/passwd",
        "$(reboot)",
        "`id`",
        "localhost\nmalicious",
        "127.0.0.1 -oG /tmp/x",
    ],
)
def test_injection_rejetee(monkeypatch, mauvaise_cible):
    appele = {"run": False}

    def fake_run(*a, **k):
        appele["run"] = True
        return _fake_completed(SAMPLE_XML)

    monkeypatch.setattr(subprocess, "run", fake_run)

    scanner = NmapScanner()
    # Même en mode force, l'injection doit être bloquée AVANT subprocess.
    assert scanner.scan(mauvaise_cible, force=True) == []
    assert appele["run"] is False
    assert NmapScanner.is_target_syntactically_valid(mauvaise_cible) is False


def test_cible_valide_acceptee_syntaxiquement():
    assert NmapScanner.is_target_syntactically_valid("127.0.0.1")
    assert NmapScanner.is_target_syntactically_valid("scanme.nmap.org")
    assert NmapScanner.is_target_syntactically_valid("192.168.0.0/24")
    assert NmapScanner.is_target_syntactically_valid("fe80::1")


# --------------------------------------------------------------------------- #
# Robustesse : binaire absent / timeout
# --------------------------------------------------------------------------- #
def test_binaire_absent_renvoie_liste(monkeypatch):
    def fake_run(*a, **k):
        raise FileNotFoundError("nmap introuvable")

    monkeypatch.setattr(subprocess, "run", fake_run)
    scanner = NmapScanner()
    assert scanner.scan("127.0.0.1") == []


def test_timeout_renvoie_liste(monkeypatch):
    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    scanner = NmapScanner()
    assert scanner.scan("127.0.0.1") == []


# --------------------------------------------------------------------------- #
# Échantillon embarqué (utilisé par la CLI démo)
# --------------------------------------------------------------------------- #
def test_demo_xml_parsable():
    services = NmapScanner.parse_xml(DEMO_NMAP_XML)
    assert len(services) == 3
    assert {s["port"] for s in services} == {22, 80, 3306}
