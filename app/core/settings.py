"""Application settings loaded from environment / .env file."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root is two levels up from this file
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Central configuration – values come from .env or env vars."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Data Sources ─────────────────────────────
    nvd_api: str | None = None

    # ── OpenAI ───────────────────────────────────
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"

    # ── PostgreSQL ───────────────────────────────
    database_url: str = (
        "postgresql://vulntriage:vulntriage_dev@localhost:5433/vulntriage"
    )

    # ── Qdrant ───────────────────────────────────
    qdrant_host: str = "localhost"
    qdrant_http_port: int = 6333
    qdrant_api_key: str = ""

    # ── Embedding ────────────────────────────────
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_dim: int = 384

    # ── Text model ───────────────────────────────
    text_model_name: str = "distilbert-base-uncased"
    text_model_mode: str = "pretrained"  # pretrained | finetune

    # ── Experiment ───────────────────────────────
    train_cutoff_date: str = "2024-12-31"
    random_seed: int = 42
    top_k_values: str = "25,50,100"

    # ── Logging ──────────────────────────────────
    log_level: str = "INFO"
    log_format: str = "json"

    # ── Safety ───────────────────────────────────
    safety_no_exploit_code: bool = True

    # ── Derived helpers ──────────────────────────
    @property
    def top_k_list(self) -> List[int]:
        return [int(v.strip()) for v in self.top_k_values.split(",")]

    @property
    def reports_dir(self) -> Path:
        p = PROJECT_ROOT / "reports"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def models_dir(self) -> Path:
        p = PROJECT_ROOT / "models"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def data_dir(self) -> Path:
        return PROJECT_ROOT / "data"


def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
