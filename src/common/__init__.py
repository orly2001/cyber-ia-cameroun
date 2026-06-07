"""Modules communs partagés par les 5 blocs du système IA & Cybersécurité Cameroun.

Ce package fixe les *contrats* (schémas de données, configuration, accès BDD,
logging) sur lesquels s'appuient tous les blocs afin de garantir leur
interopérabilité de bout en bout.
"""

from src.common import schemas  # noqa: F401

__all__ = ["schemas"]
__version__ = "0.1.0"
