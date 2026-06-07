# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Image API SOC — IA & Cybersécurité Cameroun (bloc 5)
# Image légère : on N'INSTALLE PAS torch/transformers (BERT) — trop lourd.
# Pour activer BERT, voir le commentaire plus bas dans l'étape pip install.
# ---------------------------------------------------------------------------
FROM python:3.11-slim

# Bonnes pratiques Python en conteneur
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dépendances système minimales (psycopg2-binary fournit ses propres wheels,
# mais libpq est utile pour le runtime ; curl sert au healthcheck éventuel).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1) Dépendances Python — couche cachée tant que requirements.txt ne change pas.
#    On retire torch/transformers (BERT) pour garder l'image légère.
#    Pour ACTIVER BERT : supprimer le `grep -v` ci-dessous (ou builder une
#    image dédiée) afin d'installer transformers>=4.40 et torch>=2.2.
COPY requirements.txt ./
RUN grep -viE '^(transformers|torch)\b' requirements.txt > requirements.runtime.txt \
    && pip install --no-cache-dir -r requirements.runtime.txt

# 2) Code source + données + scripts (pour entraînement au démarrage)
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY data/ ./data/

# 3) Utilisateur non-root
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data /app/models \
    && chown -R appuser:appuser /app
USER appuser

# Le module API et le port doivent rester alignés avec config.py (api_port=8000).
EXPOSE 8000

# Healthcheck léger sur l'endpoint /health exposé par l'API.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# Entraîne le modèle si absent puis lance l'API (déploiement clé en main).
ENTRYPOINT ["sh", "scripts/entrypoint.sh"]
