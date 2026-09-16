from __future__ import annotations

import logging
from pathlib import Path

import chromadb
from chromadb.config import Settings

from src.rag.embedder import encode

logger = logging.getLogger(__name__)

COLLECTION_NAME = "nist_800_53_rev5"
THREAT_REPORT_COLLECTION = "threat_report"


def get_client(chroma_dir: str | Path) -> chromadb.PersistentClient:
    chroma_dir = Path(chroma_dir)
    chroma_dir.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(
        path=str(chroma_dir),
        settings=Settings(anonymized_telemetry=False),
    )
    return client


def build_nist_index(
    client: chromadb.PersistentClient,
    controls: list[dict],
    force_rebuild: bool = False,
) -> chromadb.Collection:
    existing = [c.name for c in client.list_collections()]

    if COLLECTION_NAME in existing and not force_rebuild:
        collection = client.get_collection(COLLECTION_NAME)
        logger.info("Loaded existing NIST index (%d docs)", collection.count())
        return collection

    if COLLECTION_NAME in existing:
        client.delete_collection(COLLECTION_NAME)

    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    logger.info("Embedding %d NIST controls — this may take ~60s…", len(controls))
    texts = [c["embed_text"] for c in controls]
    embeddings = encode(texts, show_progress=True)

    ids = [c["id"] for c in controls]
    metadatas = [
        {
            "id": c["id"],
            "title": c["title"],
            "family": c["family"],
            "family_name": c["family_name"],
            "is_enhancement": str(c["is_enhancement"]),
            "prose": c["prose"][:2000],
        }
        for c in controls
    ]

    batch_size = 500
    for i in range(0, len(controls), batch_size):
        collection.add(
            ids=ids[i : i + batch_size],
            embeddings=embeddings[i : i + batch_size],
            documents=texts[i : i + batch_size],
            metadatas=metadatas[i : i + batch_size],
        )
        logger.debug(
            "Indexed batch %d/%d",
            i // batch_size + 1,
            (len(controls) + batch_size - 1) // batch_size,
        )

    logger.info("NIST index built: %d documents", collection.count())
    return collection


def build_threat_report_index(
    client: chromadb.PersistentClient,
    threat_report_text: str,
    force_rebuild: bool = False,
) -> chromadb.Collection:
    existing = [c.name for c in client.list_collections()]

    if THREAT_REPORT_COLLECTION in existing and not force_rebuild:
        collection = client.get_collection(THREAT_REPORT_COLLECTION)
        logger.info("Loaded existing threat report index (%d chunks)", collection.count())
        return collection

    if THREAT_REPORT_COLLECTION in existing:
        client.delete_collection(THREAT_REPORT_COLLECTION)

    collection = client.create_collection(
        name=THREAT_REPORT_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )

    chunks = [c.strip() for c in threat_report_text.split("---") if len(c.strip()) > 50]
    logger.info("Embedding %d threat report chunks", len(chunks))
    embeddings = encode(chunks)
    ids = [f"tr_{i}" for i in range(len(chunks))]

    collection.add(
        ids=ids,
        embeddings=embeddings,
        documents=chunks,
        metadatas=[{"chunk_index": i} for i in range(len(chunks))],
    )
    logger.info("Threat report index built: %d chunks", collection.count())
    return collection
