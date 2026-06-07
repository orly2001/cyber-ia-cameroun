# Makefile — IA & Cybersécurité Cameroun
# Recettes indentées par des TABULATIONS (requis par make).
PYTHON ?= python
PIP    ?= pip

.PHONY: help install test run-api demo train docker-up docker-down lint

help:
	@echo "Cibles disponibles :"
	@echo "  install      Installe les dépendances (requirements.txt)"
	@echo "  test         Lance la suite de tests (pytest)"
	@echo "  run-api      Démarre l'API FastAPI (uvicorn, port 8000)"
	@echo "  demo         Exécute le pipeline de démonstration"
	@echo "  train        Entraîne les modèles IA"
	@echo "  docker-up    docker compose up (db + api)"
	@echo "  docker-down  docker compose down"
	@echo "  lint         Vérifie la compilation de src/ (py_compile)"

install:
	$(PIP) install -r requirements.txt

test:
	$(PYTHON) -m pytest -q

run-api:
	$(PYTHON) -m uvicorn src.bloc5_dashboard.api.main:app --host 0.0.0.0 --port 8000 --reload

demo:
	$(PYTHON) -m src.pipeline --demo

train:
	$(PYTHON) -m src.bloc3_ia.train

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

lint:
	$(PYTHON) -m compileall -q src
