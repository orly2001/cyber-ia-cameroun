"""Détecteur de phishing basé sur un transformer multilingue (fine-tuning).

Cette classe expose la même interface que :class:`PhishingDetector` :
``predict(samples) -> list[PhishingPrediction]`` (model="bert_multilingual").

Les dépendances ``transformers`` / ``torch`` sont importées PARESSEUSEMENT et
AUCUN poids n'est téléchargé au niveau module. En leur absence :

* :meth:`is_available` renvoie ``False`` ;
* :meth:`train` lève une erreur claire et actionnable ;
* :meth:`predict` journalise un message explicite et retourne des prédictions
  NEUTRES (score 0.0, ``is_phishing`` False) afin de ne pas casser le pipeline.

Modèle par défaut : ``settings.bert_model_name`` (bert-base-multilingual-cased),
adapté au français et à l'anglais des messages camerounais. Les poids
fine-tunés sont sauvegardés dans ``MODELS_DIR/bert_phishing/``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from src.common.config import MODELS_DIR, settings
from src.common.logging_conf import get_logger
from src.common.schemas import PhishingPrediction, PhishingSample

logger = get_logger(__name__)

# Répertoire de persistance du modèle fine-tuné (poids + tokenizer + config).
DEFAULT_MODEL_DIR = MODELS_DIR / "bert_phishing"

_INSTALL_HINT = (
    "Dépendances manquantes pour BERT. Installez-les avec : "
    "pip install 'transformers>=4.30' 'torch>=2.0'"
)


def _deps_available() -> bool:
    """Indique si ``transformers`` ET ``torch`` sont importables (import lazy)."""
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError:
        return False
    return True


class BertPhishingDetector:
    """Wrapper paresseux d'un modèle transformers de classification de phishing."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        device: Optional[str] = None,
        model_dir: Optional[Path] = None,
        max_length: int = 256,
    ) -> None:
        """Initialise le détecteur sans charger ni télécharger de modèle (lazy).

        Args:
            model_name: identifiant HuggingFace du modèle de base (par défaut
                ``settings.bert_model_name``).
            device: ``'cpu'`` ou ``'cuda'``. Si ``None``, CPU par défaut (le GPU
                n'est sélectionné automatiquement que par les méthodes lourdes si
                ``torch.cuda.is_available()``).
            model_dir: répertoire de persistance du modèle fine-tuné (par défaut
                ``MODELS_DIR/bert_phishing/``).
            max_length: longueur maximale de tokenisation.
        """
        self.model_name = model_name or settings.bert_model_name
        self.device = device or "cpu"
        self.model_dir = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
        self.max_length = max_length
        self.threshold = settings.phishing_threshold
        # Objets transformers chargés à la demande (jamais à l'import).
        self._model = None
        self._tokenizer = None

    # ------------------------------------------------------------------ #
    # Disponibilité
    # ------------------------------------------------------------------ #
    @staticmethod
    def is_available() -> bool:
        """Renvoie ``True`` si ``transformers`` et ``torch`` sont importables."""
        return _deps_available()

    @property
    def is_loaded(self) -> bool:
        """Indique si un modèle fine-tuné est chargé en mémoire."""
        return self._model is not None and self._tokenizer is not None

    def _resolve_device(self) -> str:
        """Détermine le device effectif (CPU par défaut, CUDA si demandé/dispo)."""
        try:
            import torch
        except ImportError:
            return "cpu"
        if self.device == "cuda" and torch.cuda.is_available():
            return "cuda"
        return "cpu"

    # ------------------------------------------------------------------ #
    # Entraînement (fine-tuning)
    # ------------------------------------------------------------------ #
    def train(
        self,
        samples: List[PhishingSample],
        epochs: int = 2,
        batch_size: int = 8,
    ) -> "BertPhishingDetector":
        """Fine-tune un modèle de classification de séquences sur les samples.

        Utilise l'API ``Trainer`` de ``transformers`` lorsqu'elle est disponible,
        avec un repli sur une boucle PyTorch simple. Seuls les échantillons
        labellisés (``label`` ∈ {0, 1}) sont utilisés. Le modèle, le tokenizer et
        la configuration sont sauvegardés dans ``self.model_dir``.

        Args:
            samples: échantillons prétraités et labellisés.
            epochs: nombre d'époques de fine-tuning.
            batch_size: taille de batch d'entraînement.

        Returns:
            ``self`` pour chaînage.

        Raises:
            RuntimeError: si ``transformers``/``torch`` sont absents, ou si les
                données labellisées sont insuffisantes (< 2 classes).
        """
        if not self.is_available():
            raise RuntimeError(_INSTALL_HINT)

        texts: List[str] = []
        labels: List[int] = []
        for s in samples:
            if s.label is None:
                continue
            texts.append(s.clean_text or s.raw_text)
            labels.append(int(s.label))

        if len(set(labels)) < 2:
            raise RuntimeError(
                "Fine-tuning impossible : moins de 2 classes labellisées "
                f"({len(labels)} échantillon(s)). Annotez davantage de données."
            )

        import torch
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
        )

        device = self._resolve_device()
        logger.info(
            "Fine-tuning BERT '%s' sur %d échantillon(s) (%d époque(s), device=%s).",
            self.model_name,
            len(labels),
            epochs,
            device,
        )

        tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name, num_labels=2
        )
        model.to(device)

        # Tentative via Trainer (API haut niveau), repli sur boucle manuelle.
        try:
            self._train_with_trainer(
                model, tokenizer, texts, labels, epochs, batch_size, device
            )
        except Exception as exc:  # Trainer indisponible / incompatible
            logger.warning(
                "Trainer indisponible (%s) ; repli sur boucle PyTorch simple.", exc
            )
            self._train_with_loop(
                model, tokenizer, texts, labels, epochs, batch_size, device, torch
            )

        self._model = model
        self._tokenizer = tokenizer
        self.save()
        return self

    def _train_with_trainer(
        self, model, tokenizer, texts, labels, epochs, batch_size, device
    ) -> None:
        """Fine-tuning via l'API ``transformers.Trainer``."""
        import torch
        from transformers import Trainer, TrainingArguments

        class _Dataset(torch.utils.data.Dataset):
            def __init__(self, encodings, labels):
                self.encodings = encodings
                self.labels = labels

            def __len__(self) -> int:
                return len(self.labels)

            def __getitem__(self, idx):
                item = {k: v[idx] for k, v in self.encodings.items()}
                item["labels"] = torch.tensor(self.labels[idx])
                return item

        encodings = tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        dataset = _Dataset(encodings, labels)

        args = TrainingArguments(
            output_dir=str(self.model_dir / "_trainer_tmp"),
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            logging_steps=10,
            save_strategy="no",
            report_to=[],
            no_cuda=(device == "cpu"),
        )
        trainer = Trainer(model=model, args=args, train_dataset=dataset)
        trainer.train()
        logger.info("Fine-tuning terminé via Trainer.")

    def _train_with_loop(
        self, model, tokenizer, texts, labels, epochs, batch_size, device, torch
    ) -> None:
        """Repli : boucle d'entraînement PyTorch minimale (sans Trainer)."""
        from torch.optim import AdamW

        model.train()
        optimizer = AdamW(model.parameters(), lr=5e-5)
        n = len(texts)
        for epoch in range(epochs):
            total_loss = 0.0
            for start in range(0, n, batch_size):
                batch_texts = texts[start : start + batch_size]
                batch_labels = torch.tensor(
                    labels[start : start + batch_size], device=device
                )
                enc = tokenizer(
                    batch_texts,
                    truncation=True,
                    padding=True,
                    max_length=self.max_length,
                    return_tensors="pt",
                ).to(device)
                optimizer.zero_grad()
                out = model(**enc, labels=batch_labels)
                out.loss.backward()
                optimizer.step()
                total_loss += float(out.loss.item())
            logger.info(
                "Époque %d/%d — perte moyenne : %.4f",
                epoch + 1,
                epochs,
                total_loss / max(1, (n + batch_size - 1) // batch_size),
            )
        model.eval()
        logger.info("Fine-tuning terminé via boucle PyTorch.")

    # ------------------------------------------------------------------ #
    # Persistance
    # ------------------------------------------------------------------ #
    def save(self, model_dir: Optional[Path] = None) -> Optional[Path]:
        """Sauvegarde le modèle fine-tuné et son tokenizer dans un répertoire.

        Args:
            model_dir: répertoire cible (par défaut ``self.model_dir``).

        Returns:
            Le chemin du répertoire écrit, ou ``None`` si rien à sauvegarder.
        """
        if not self.is_loaded:
            logger.warning("Aucun modèle BERT chargé à sauvegarder.")
            return None
        target = Path(model_dir) if model_dir else self.model_dir
        target.mkdir(parents=True, exist_ok=True)
        self._model.save_pretrained(str(target))
        self._tokenizer.save_pretrained(str(target))
        logger.info("Modèle BERT sauvegardé : %s", target)
        return target

    def load(self, model_dir: Optional[Path] = None) -> "BertPhishingDetector":
        """Charge un modèle fine-tuné depuis ``self.model_dir`` (lazy, sans réseau).

        Args:
            model_dir: répertoire source (par défaut ``self.model_dir``).

        Returns:
            ``self``. Le modèle reste non chargé (prédictions neutres) si les
            dépendances ou les poids sont absents.
        """
        if not self.is_available():
            logger.error(_INSTALL_HINT)
            return self

        source = Path(model_dir) if model_dir else self.model_dir
        if not source.exists():
            logger.warning(
                "Modèle BERT introuvable (%s) ; entraînez-le d'abord "
                "(python -m src.bloc3_ia.train --model bert).",
                source,
            )
            return self

        try:
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )

            device = self._resolve_device()
            self._tokenizer = AutoTokenizer.from_pretrained(str(source))
            self._model = AutoModelForSequenceClassification.from_pretrained(
                str(source)
            )
            self._model.to(device)
            self._model.eval()
            logger.info("Modèle BERT chargé : %s (device=%s)", source, device)
        except Exception as exc:  # poids corrompus, incompatibilité, etc.
            logger.error("Échec du chargement du modèle BERT (%s) : %s", source, exc)
            self._model = None
            self._tokenizer = None
        return self

    # ------------------------------------------------------------------ #
    # Prédiction
    # ------------------------------------------------------------------ #
    def predict(self, samples: List[PhishingSample]) -> List[PhishingPrediction]:
        """Prédit le phishing via le transformer multilingue fine-tuné.

        Charge le modèle persistant à la demande si nécessaire. ``is_phishing``
        est dérivé de ``settings.phishing_threshold``.

        Args:
            samples: échantillons (idéalement prétraités).

        Returns:
            Liste de :class:`PhishingPrediction` (model="bert_multilingual"). Si
            les dépendances/poids sont absents, retourne des prédictions NEUTRES
            (score 0.0, ``is_phishing`` False) pour ne pas casser le pipeline.
        """
        if not self.is_available():
            logger.warning(
                "BERT indisponible (deps absentes) : prédictions neutres. %s",
                _INSTALL_HINT,
            )
            return self._neutral_predictions(samples)

        if not self.is_loaded:
            self.load()
        if not self.is_loaded:
            logger.warning(
                "Aucun modèle BERT chargé : prédictions neutres renvoyées."
            )
            return self._neutral_predictions(samples)

        try:
            scores = self._infer_scores(samples)
        except Exception as exc:
            logger.error("Échec d'inférence BERT (%s) ; prédictions neutres.", exc)
            return self._neutral_predictions(samples)

        predictions: List[PhishingPrediction] = []
        for sample, score in zip(samples, scores):
            predictions.append(
                PhishingPrediction(
                    sample_id=sample.id,
                    is_phishing=score >= self.threshold,
                    score=round(float(score), 4),
                    model="bert_multilingual",
                )
            )
        return predictions

    def _infer_scores(self, samples: List[PhishingSample]) -> List[float]:
        """Calcule la probabilité de phishing (classe 1) pour chaque échantillon."""
        import torch

        texts = [s.clean_text or s.raw_text for s in samples]
        device = self._resolve_device()
        scores: List[float] = []
        with torch.no_grad():
            for start in range(0, len(texts), 16):
                batch = texts[start : start + 16]
                enc = self._tokenizer(
                    batch,
                    truncation=True,
                    padding=True,
                    max_length=self.max_length,
                    return_tensors="pt",
                ).to(device)
                logits = self._model(**enc).logits
                proba = torch.softmax(logits, dim=-1)
                # Index 1 = classe positive (phishing).
                scores.extend(proba[:, 1].cpu().tolist())
        return scores

    @staticmethod
    def _neutral_predictions(
        samples: List[PhishingSample],
    ) -> List[PhishingPrediction]:
        """Retourne des prédictions neutres (score 0.0) pour chaque échantillon."""
        return [
            PhishingPrediction(
                sample_id=s.id,
                is_phishing=False,
                score=0.0,
                model="bert_multilingual",
            )
            for s in samples
        ]
