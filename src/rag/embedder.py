from __future__ import annotations

import logging
from functools import lru_cache

from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

MODEL_NAME = "all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def get_embedder() -> SentenceTransformer:
    logger.info("Loading sentence-transformer model: %s", MODEL_NAME)
    model = SentenceTransformer(MODEL_NAME)
    dim = getattr(model, "get_embedding_dimension", model.get_sentence_embedding_dimension)()
    logger.info("Embedder ready (dim=%d)", dim)
    return model


def encode(texts: list[str], batch_size: int = 64, show_progress: bool = False) -> list[list[float]]:
    model = get_embedder()
    embeddings = model.encode(
        texts,
        batch_size=batch_size,
        show_progress_bar=show_progress,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )
    return embeddings.tolist()
