"""Configuration centralisee chargee depuis l'environnement (.env)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:  # repli si pydantic-settings non installe
    from pydantic import BaseSettings  # type: ignore
    SettingsConfigDict = dict  # type: ignore


# Racine du projet (.../cyber-ia-cameroun)
ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models"
SAMPLES_DIR = DATA_DIR / "samples"
# Datasets externes telecharges (sources publiques reelles) et mode hors-ligne.
EXTERNAL_DIR = DATA_DIR / "external"
# Datasets derives/assembles (dataset d'entrainement consolide).
PROCESSED_DIR = DATA_DIR / "processed"

# Creation paresseuse des dossiers de donnees (idempotent, sans effet de bord
# si deja presents). Garantit que les fonctions d'acquisition peuvent ecrire.
for _d in (DATA_DIR, SAMPLES_DIR, EXTERNAL_DIR, PROCESSED_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


class Settings(BaseSettings):
    # --- Application ---
    app_name: str = "IA & Cybersecurite Cameroun"
    environment: str = "development"
    log_level: str = "INFO"

    # --- Base de donnees ---
    database_url: str = "postgresql+psycopg2://soc:soc@localhost:5432/soc_cm"
    # Repli SQLite pour le dev sans PostgreSQL :
    sqlite_fallback: str = f"sqlite:///{(DATA_DIR / 'soc_dev.db').as_posix()}"
    use_sqlite_fallback: bool = True

    # --- Sources externes ---
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    zap_api_url: str = "http://localhost:8080"
    zap_api_key: str = ""

    # --- Moteur IA ---
    phishing_threshold: float = 0.5
    bert_model_name: str = "bert-base-multilingual-cased"

    # --- API ---
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    # Cle d'API protegeant les endpoints qui modifient l'etat (env API_KEY).
    # Vide => authentification desactivee (mode dev permissif, voir security.py).
    api_key: str = ""

    model_config = SettingsConfigDict(
        env_file=str(ROOT_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def effective_database_url(self) -> str:
        """URL reellement utilisee (PostgreSQL ou repli SQLite)."""
        return self.sqlite_fallback if self.use_sqlite_fallback else self.database_url


@lru_cache
def get_settings() -> "Settings":
    return Settings()


settings = get_settings()
