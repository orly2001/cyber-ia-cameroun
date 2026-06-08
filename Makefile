# Makefile — IA & Cybersécurité Cameroun
# Recettes indentées par des TABULATIONS (requis par make).
PYTHON ?= python
PIP    ?= pip

.PHONY: help install test smoke run-api demo train docker-up docker-down deploy deploy-down run-all lint scan-demo-up scan-demo-down

help:
	@echo "Cibles disponibles :"
	@echo "  install      Installe les dépendances (requirements.txt)"
	@echo "  test         Lance la suite de tests (pytest)"
	@echo "  smoke        Smoke-test end-to-end de l API (tous endpoints)"
	@echo "  run-api      Démarre l API FastAPI (uvicorn, port 8000)"
	@echo "  run-all      Lance API + frontend en local (scripts/run_all.sh)"
	@echo "  demo         Exécute le pipeline de démonstration"
	@echo "  train        Entraîne les modèles IA"
	@echo "  deploy       Déploiement Docker COMPLET via deploy.sh"
	@echo "  deploy-down  Arrête la stack Docker"
	@echo "  docker-up    docker compose up --build -d (db + api + web)"
	@echo "  docker-down  docker compose down"
	@echo "  scan-demo-up   Démarre la stack de démo scan (ZAP + DVWA)"
	@echo "  scan-demo-down Arrête la stack de démo scan"
	@echo "  lint         Vérifie la compilation de src/ (py_compile)"

install:
	$(PIP) install -r requirements.txt

test:
	$(PYTHON) -m pytest -q

smoke:
	$(PYTHON) -m scripts.smoke_test

run-api:
	$(PYTHON) -m uvicorn src.bloc5_dashboard.api.main:app --host 0.0.0.0 --port 8000 --reload

run-all:
	bash scripts/run_all.sh

demo:
	$(PYTHON) -m src.pipeline --demo

train:
	$(PYTHON) -m src.bloc3_ia.train --model tfidf --seed 42

deploy:
	bash deploy.sh up

deploy-down:
	bash deploy.sh down

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

scan-demo-up:
	docker compose -f docker-compose.scan.yml up -d

scan-demo-down:
	docker compose -f docker-compose.scan.yml down

lint:
	$(PYTHON) -m compileall -q src
