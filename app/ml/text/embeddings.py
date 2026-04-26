"""Text embedding pipeline for CVE descriptions.

Encodes vulnerability descriptions using a pre-trained sentence-transformer
model, then applies PCA for dimensionality reduction to produce compact
feature vectors suitable for XGBoost tree models.

Architecture
------------
1. Encode descriptions with ``all-MiniLM-L6-v2`` → 384-dim vectors
2. PCA reduce to ``n_components`` (default 32) → compact features
3. Append as ``emb_0 … emb_31`` columns to the feature DataFrame
4. Cache embeddings on disk to avoid recomputation

The PCA is fit ONLY on training data to prevent data leakage.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

from app.core.logging import get_logger
from app.core.settings import get_settings

log = get_logger(__name__)

# ── Defaults ────────────────────────────────────────────────────────────
DEFAULT_MODEL = "all-MiniLM-L6-v2"
DEFAULT_PCA_COMPONENTS = 32
EMBEDDING_DIM = 384   # output dim of all-MiniLM-L6-v2
BATCH_SIZE = 512


class TextEmbeddingPipeline:
    """Encode CVE descriptions → PCA-reduced feature vectors.

    Usage::

        pipe = TextEmbeddingPipeline(n_components=32)
        pipe.fit(train_texts)                      # fit PCA on train only
        train_emb = pipe.transform(train_texts)    # (n_train, 32)
        test_emb = pipe.transform(test_texts)      # (n_test, 32)

        # Append as DataFrame columns
        emb_df = pipe.to_dataframe(train_emb)      # cols: emb_0..emb_31
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        n_components: int = DEFAULT_PCA_COMPONENTS,
        cache_dir: Optional[Path] = None,
    ) -> None:
        self.model_name = model_name
        self.n_components = n_components
        self.cache_dir = cache_dir or (get_settings().models_dir / "embeddings_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self._st_model = None
        self._pca: Optional[PCA] = None
        self._scaler: Optional[StandardScaler] = None

    # ── Encoding ────────────────────────────────────────────────────────

    def _load_st_model(self):
        """Lazy-load the sentence-transformer model."""
        if self._st_model is None:
            from sentence_transformers import SentenceTransformer
            log.info("loading_sentence_transformer", model=self.model_name)
            self._st_model = SentenceTransformer(self.model_name)
        return self._st_model

    def encode_raw(
        self,
        texts: List[str],
        *,
        show_progress: bool = True,
        cache_key: Optional[str] = None,
    ) -> np.ndarray:
        """Encode texts to raw 384-dim embeddings (before PCA).

        If *cache_key* is provided, embeddings are cached on disk.
        """
        # Check cache
        if cache_key:
            cache_path = self.cache_dir / f"{cache_key}.npy"
            if cache_path.exists():
                log.info("embeddings_cache_hit", key=cache_key)
                emb = np.load(cache_path)
                if emb.shape[0] == len(texts):
                    return emb
                log.warning("cache_size_mismatch", cached=emb.shape[0], expected=len(texts))

        # Encode
        model = self._load_st_model()
        t0 = time.time()
        log.info("encoding_texts", n=len(texts))

        embeddings = model.encode(
            texts,
            show_progress_bar=show_progress,
            convert_to_numpy=True,
            batch_size=BATCH_SIZE,
            normalize_embeddings=True,  # L2 normalise → cosine sim = dot product
        )

        elapsed = time.time() - t0
        log.info("encoding_done", n=len(texts), elapsed_s=round(elapsed, 1))

        # Save cache
        if cache_key:
            cache_path = self.cache_dir / f"{cache_key}.npy"
            np.save(cache_path, embeddings)
            log.info("embeddings_cached", key=cache_key, path=str(cache_path))

        return embeddings

    # ── PCA fitting ─────────────────────────────────────────────────────

    def fit(
        self,
        texts: List[str],
        *,
        cache_key: str = "train_raw",
    ) -> "TextEmbeddingPipeline":
        """Fit PCA on training texts (encode + fit PCA).

        Must be called before transform(). The PCA is fit only on
        train data to prevent information leakage from the test set.
        """
        raw = self.encode_raw(texts, cache_key=cache_key)

        # Standardise before PCA for better variance capture
        self._scaler = StandardScaler()
        scaled = self._scaler.fit_transform(raw)

        self._pca = PCA(
            n_components=min(self.n_components, raw.shape[1], raw.shape[0]),
            random_state=42,
        )
        self._pca.fit(scaled)

        explained = self._pca.explained_variance_ratio_.sum()
        log.info(
            "pca_fit",
            n_components=self._pca.n_components_,
            explained_variance=round(explained, 4),
        )
        return self

    def transform(
        self,
        texts: List[str],
        *,
        cache_key: Optional[str] = None,
    ) -> np.ndarray:
        """Encode + PCA-transform texts → (n, n_components) array.

        PCA must have been fit first via ``fit()``.
        """
        if self._pca is None or self._scaler is None:
            raise RuntimeError("Must call fit() before transform()")

        raw = self.encode_raw(texts, cache_key=cache_key)
        scaled = self._scaler.transform(raw)
        reduced = self._pca.transform(scaled)
        return reduced

    def fit_transform(
        self,
        texts: List[str],
        *,
        cache_key: str = "train_raw",
    ) -> np.ndarray:
        """Fit PCA on texts and return transformed embeddings."""
        self.fit(texts, cache_key=cache_key)
        # Re-use the raw embeddings already cached during fit
        raw = self.encode_raw(texts, cache_key=cache_key)
        scaled = self._scaler.transform(raw)
        return self._pca.transform(scaled)

    # ── Raw-array variants (skip encode step) ───────────────────────────

    def fit_transform_raw(self, raw: np.ndarray) -> np.ndarray:
        """Fit PCA on pre-encoded raw embeddings and return transformed.

        Use when you already have raw embeddings (e.g. from encode_raw)
        and want to fit+transform in one step without re-encoding.
        """
        self._scaler = StandardScaler()
        scaled = self._scaler.fit_transform(raw)

        self._pca = PCA(
            n_components=min(self.n_components, raw.shape[1], raw.shape[0]),
            random_state=42,
        )
        reduced = self._pca.fit_transform(scaled)

        explained = self._pca.explained_variance_ratio_.sum()
        log.info(
            "pca_fit",
            n_components=self._pca.n_components_,
            explained_variance=round(explained, 4),
        )
        return reduced

    def transform_raw(self, raw: np.ndarray) -> np.ndarray:
        """Transform pre-encoded raw embeddings using already-fitted PCA.

        PCA must have been fit first via ``fit()``, ``fit_transform()``,
        or ``fit_transform_raw()``.
        """
        if self._pca is None or self._scaler is None:
            raise RuntimeError("Must call fit() or fit_transform_raw() before transform_raw()")
        scaled = self._scaler.transform(raw)
        return self._pca.transform(scaled)

    # ── DataFrame helpers ───────────────────────────────────────────────

    @staticmethod
    def to_dataframe(
        embeddings: np.ndarray,
        prefix: str = "emb_",
    ) -> pd.DataFrame:
        """Convert embedding array to DataFrame with named columns."""
        n_cols = embeddings.shape[1]
        columns = [f"{prefix}{i}" for i in range(n_cols)]
        return pd.DataFrame(embeddings, columns=columns)

    @staticmethod
    def embedding_column_names(n_components: int = DEFAULT_PCA_COMPONENTS, prefix: str = "emb_") -> List[str]:
        """Return the expected embedding column names."""
        return [f"{prefix}{i}" for i in range(n_components)]

    # ── Persistence ─────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> Path:
        """Save the fitted PCA + scaler pipeline."""
        if path is None:
            path = get_settings().models_dir / "text_embedding_pipeline.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)

        joblib.dump({
            "pca": self._pca,
            "scaler": self._scaler,
            "model_name": self.model_name,
            "n_components": self.n_components,
        }, path)
        log.info("embedding_pipeline_saved", path=str(path))
        return path

    def load(self, path: Optional[Path] = None) -> "TextEmbeddingPipeline":
        """Load a saved PCA + scaler pipeline."""
        if path is None:
            path = get_settings().models_dir / "text_embedding_pipeline.joblib"

        data = joblib.load(path)
        self._pca = data["pca"]
        self._scaler = data["scaler"]
        self.model_name = data["model_name"]
        self.n_components = data["n_components"]
        log.info("embedding_pipeline_loaded", path=str(path))
        return self
