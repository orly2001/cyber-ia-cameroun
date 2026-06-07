"""Configuration partagée des tests (pytest).

Force l'usage du repli SQLite et garantit que la racine du projet est sur le
``sys.path`` pour que ``import src...`` fonctionne quelle que soit la façon dont
pytest est invoqué.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Racine du projet (…/cyber-ia-cameroun) = parent du dossier tests/.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# En test, on ne dépend jamais de PostgreSQL : repli SQLite forcé.
os.environ.setdefault("USE_SQLITE_FALLBACK", "true")
