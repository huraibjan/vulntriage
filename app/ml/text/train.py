"""Stage 2: Text-based exploitability prediction using Transformers.

Supports two modes:
  - pretrained: Use a pre-trained model for zero-shot or feature extraction
  - finetune:   Fine-tune a sequence classifier on our labeled dataset

Uses Hugging Face transformers + sentence-transformers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score

from app.core.logging import get_logger
from app.core.settings import get_settings

log = get_logger(__name__)


class TextPredictor:
    """Text-based exploitability predictor.

    Modes:
        pretrained – Use sentence embeddings + a simple logistic head.
        finetune   – Fine-tune a sequence classification model.
    """

    def __init__(self, mode: str = "pretrained", model_name: Optional[str] = None) -> None:
        settings = get_settings()
        self.mode = mode
        self.model_name = model_name or settings.text_model_name
        self._model = None
        self._tokenizer = None
        self._embedding_model = None
        self._head = None  # simple classifier head for pretrained mode

    def _load_embedding_model(self):
        """Load sentence-transformers model for pretrained mode."""
        if self._embedding_model is None:
            from sentence_transformers import SentenceTransformer
            self._embedding_model = SentenceTransformer(self.model_name)
        return self._embedding_model

    def _load_classifier(self):
        """Load a HuggingFace sequence classification model for finetune mode."""
        if self._model is None:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name, num_labels=2
            )
        return self._model, self._tokenizer

    def train_pretrained_mode(
        self,
        texts: List[str],
        labels: List[int],
    ) -> Dict[str, Any]:
        """Train a simple logistic regression on sentence embeddings.

        This is the fast path that doesn't require GPU fine-tuning.
        """
        from sklearn.linear_model import LogisticRegression

        log.info("text_training_pretrained", n_samples=len(texts))
        model = self._load_embedding_model()
        embeddings = model.encode(texts, show_progress_bar=False, convert_to_numpy=True)

        clf = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
        clf.fit(embeddings, labels)
        self._head = clf

        # Training metrics
        y_prob = clf.predict_proba(embeddings)[:, 1]
        metrics = {
            "mode": "pretrained",
            "model": self.model_name,
            "n_samples": len(texts),
            "train_pr_auc": float(average_precision_score(labels, y_prob)),
            "train_f1": float(f1_score(labels, (y_prob >= 0.5).astype(int), zero_division=0)),
        }
        log.info("text_pretrained_trained", **metrics)
        return metrics

    def train_finetune_mode(
        self,
        texts: List[str],
        labels: List[int],
        *,
        epochs: int = 3,
        batch_size: int = 8,
        lr: float = 2e-5,
    ) -> Dict[str, Any]:
        """Fine-tune a transformer sequence classifier.

        Requires more compute but gives best results.
        """
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )
        from torch.utils.data import Dataset

        log.info("text_training_finetune", n_samples=len(texts), epochs=epochs)

        tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name, num_labels=2
        )

        # Tokenize
        encodings = tokenizer(
            texts, truncation=True, padding=True, max_length=256, return_tensors="pt"
        )

        class VulnDataset(Dataset):
            def __init__(self, enc, labs):
                self.enc = enc
                self.labs = labs

            def __len__(self):
                return len(self.labs)

            def __getitem__(self, idx):
                item = {k: v[idx] for k, v in self.enc.items()}
                item["labels"] = torch.tensor(self.labs[idx], dtype=torch.long)
                return item

        dataset = VulnDataset(encodings, labels)

        settings = get_settings()
        output_dir = settings.models_dir / "text_finetune"
        output_dir.mkdir(parents=True, exist_ok=True)

        training_args = TrainingArguments(
            output_dir=str(output_dir),
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            learning_rate=lr,
            weight_decay=0.01,
            logging_steps=10,
            save_strategy="epoch",
            seed=settings.random_seed,
            report_to="none",
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=dataset,
        )

        trainer.train()

        self._model = model
        self._tokenizer = tokenizer

        metrics = {
            "mode": "finetune",
            "model": self.model_name,
            "n_samples": len(texts),
            "epochs": epochs,
        }
        log.info("text_finetune_trained", **metrics)
        return metrics

    def predict(self, texts: List[str]) -> np.ndarray:
        """Predict exploitability probabilities for a list of texts.

        Returns array of probabilities (positive class).
        """
        if self.mode == "pretrained":
            return self._predict_pretrained(texts)
        else:
            return self._predict_finetune(texts)

    def _predict_pretrained(self, texts: List[str]) -> np.ndarray:
        """Predict using sentence embeddings + logistic head."""
        model = self._load_embedding_model()
        embeddings = model.encode(texts, show_progress_bar=False, convert_to_numpy=True)

        if self._head is None:
            # No trained head – return uniform 0.5
            log.warning("text_no_head", msg="No classifier head; returning 0.5")
            return np.full(len(texts), 0.5)

        probs = self._head.predict_proba(embeddings)[:, 1]
        return probs

    def _predict_finetune(self, texts: List[str]) -> np.ndarray:
        """Predict using fine-tuned transformer."""
        model, tokenizer = self._load_classifier()
        model.eval()

        encodings = tokenizer(
            texts, truncation=True, padding=True, max_length=256, return_tensors="pt"
        )

        with torch.no_grad():
            outputs = model(**encodings)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)[:, 1].numpy()

        return probs

    def evaluate(
        self,
        texts: List[str],
        labels: List[int],
    ) -> Dict[str, Any]:
        """Evaluate the text model on a test set."""
        y_prob = self.predict(texts)
        y_pred = (y_prob >= 0.5).astype(int)
        y_true = np.array(labels)

        metrics: Dict[str, Any] = {
            "mode": self.mode,
            "model": self.model_name,
            "n_test": len(texts),
        }

        try:
            metrics["pr_auc"] = float(average_precision_score(y_true, y_prob))
        except ValueError:
            metrics["pr_auc"] = 0.0

        metrics["brier_score"] = float(brier_score_loss(y_true, y_prob))
        metrics["f1"] = float(f1_score(y_true, y_pred, zero_division=0))

        return metrics

    def save(self, path: Optional[Path] = None) -> Path:
        """Save the model artifacts."""
        import joblib

        settings = get_settings()
        if path is None:
            path = settings.models_dir / f"text_{self.mode}"

        path.mkdir(parents=True, exist_ok=True)

        if self.mode == "pretrained" and self._head is not None:
            joblib.dump(self._head, path / "head.joblib")
            (path / "config.json").write_text(json.dumps({
                "mode": self.mode, "model_name": self.model_name
            }))
        elif self.mode == "finetune" and self._model is not None:
            self._model.save_pretrained(str(path))
            self._tokenizer.save_pretrained(str(path))

        log.info("text_model_saved", path=str(path))
        return path

    def load(self, path: Optional[Path] = None) -> None:
        """Load saved model artifacts."""
        import joblib

        settings = get_settings()
        if path is None:
            path = settings.models_dir / f"text_{self.mode}"

        if self.mode == "pretrained":
            head_path = path / "head.joblib"
            if head_path.exists():
                self._head = joblib.load(head_path)
                log.info("text_head_loaded", path=str(head_path))
        elif self.mode == "finetune":
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            self._model = AutoModelForSequenceClassification.from_pretrained(str(path))
            self._tokenizer = AutoTokenizer.from_pretrained(str(path))
            log.info("text_finetune_loaded", path=str(path))
