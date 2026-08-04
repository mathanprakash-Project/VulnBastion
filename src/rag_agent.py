"""
NIST 800-53 RAG Index Builder & Retriever
Embeds NIST controls into ChromaDB for semantic search using BGE model.
"""
import pandas as pd
import chromadb
from chromadb.utils import embedding_functions
from pathlib import Path
import logging
import os
os.environ["ANONYMIZED_TELEMETRY"] = "False"
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
from pathlib import Path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
NIST_CSV_PATH = _PROJECT_ROOT / "data" / "external" / "NIST_SP-800-53_rev5_catalog_load.csv"

CHROMA_DIR = "../data/chroma_nist"
COLLECTION_NAME = "nist_800_53"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
BATCH_SIZE = 100

# BGE Query Prefix for asymmetric retrieval
BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "


def load_nist_csv() -> pd.DataFrame:
    """Load and validate NIST CSV file."""
    logger.info(f"Loading NIST CSV from {NIST_CSV_PATH}")
    try:
        df = pd.read_csv(str(NIST_CSV_PATH))
        logger.info(f"Loaded {len(df)} rows from NIST CSV")
        return df
    except FileNotFoundError:
        logger.error(f"NIST CSV not found at {NIST_CSV_PATH}")
        raise

def build_chunks(df: pd.DataFrame) -> list[dict]:
    """
    Convert each NIST control row into a searchable text chunk.
    
    Each chunk contains:
    - identifier (e.g., SI-2)
    - name (e.g., Flaw Remediation)
    - control_text (the requirement)
    - discussion (contextual guidance)
    
    Withdrawn controls are filtered out to reduce retrieval noise.
    """
    chunks = []
    skipped = 0
    
    for _, row in df.iterrows():
        identifier = str(row.get("identifier", "")).strip()
        name = str(row.get("name", "")).strip()
        control_text = str(row.get("control_text", "")).strip()
        discussion = str(row.get("discussion", "")).strip()
        related = str(row.get("related", "")).strip()
        
        # Skip withdrawn or empty controls
        if not identifier or not control_text or control_text.lower() == "nan":
            skipped += 1
            continue
        
        if "withdrawn" in control_text.lower():
            skipped += 1
            continue
        
        # Build consolidated document text
        doc = f"{identifier} — {name}\n\nControl: {control_text}"
        
        if discussion and discussion.lower() != "nan":
            doc += f"\n\nDiscussion: {discussion}"
        
        chunks.append({
            "id": identifier,
            "document": doc,
            "metadata": {
                "identifier": identifier,
                "name": name,
                "family": identifier.split("-")[0] if "-" in identifier else identifier,
                "related": related if related.lower() != "nan" else "",
            }
        })
    
    logger.info(f"Created {len(chunks)} chunks (skipped {skipped} withdrawn/empty)")
    return chunks


def initialize_embedder() -> embedding_functions.SentenceTransformerEmbeddingFunction:
    """Initialize BGE sentence-transformer embedding function."""
    logger.info(f"Initializing embedding model: {EMBEDDING_MODEL}")
    return embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )


def build_index(force_rebuild: bool = True) -> chromadb.Collection:
    """
    Build or load ChromaDB index for NIST controls.
    
    If force_rebuild=False, loads existing index from disk (fast).
    If force_rebuild=True, deletes and rebuilds from scratch.
    
    Default is True to ensure fresh BGE embeddings.
    """
    Path(CHROMA_DIR).mkdir(parents=True, exist_ok=True)
    
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    embedder = initialize_embedder()
    
    # Check if collection exists
    existing_collections = [c.name for c in client.list_collections()]
    collection_exists = COLLECTION_NAME in existing_collections
    
    if collection_exists and not force_rebuild:
        logger.info(f"Loading existing collection '{COLLECTION_NAME}'")
        return client.get_collection(
            COLLECTION_NAME,
            embedding_function=embedder
        )
    
    # Delete existing collection if rebuild requested
    if collection_exists and force_rebuild:
        logger.info("Deleting existing collection for rebuild")
        client.delete_collection(COLLECTION_NAME)
    
    # Create new collection
    logger.info("Creating new ChromaDB collection")
    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedder,
        metadata={"hnsw:space": "cosine"},
    )
    
    # Load and chunk data
    df = load_nist_csv()
    chunks = build_chunks(df)
    
    # Add chunks in batches
    logger.info(f"Adding {len(chunks)} chunks to collection in batches of {BATCH_SIZE}")
    for i in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[i:i + BATCH_SIZE]
        collection.add(
            ids=[c["id"] for c in batch],
            documents=[c["document"] for c in batch],
            metadatas=[c["metadata"] for c in batch],
        )
        logger.debug(f"Added batch {i // BATCH_SIZE + 1}")
    
    logger.info(f"✓ Index built successfully. {collection.count()} controls indexed.")
    return collection


def retrieve_controls(
    query: str,
    top_k: int = 3,
    family_filter: list[str] = None
) -> list[dict]:
    """
    Retrieve the top-k most relevant NIST controls for a query.
    
    Uses BGE model with query prefix for asymmetric retrieval optimization.
    
    Args:
        query: The search query (natural language)
        top_k: Number of results to return
        family_filter: Optional list of control families to filter (e.g., ['SI', 'RA'])
    
    Returns:
        List of dicts with: identifier, name, document, distance
    """
    collection = build_index(force_rebuild=False)
    
    # Apply BGE query prefix for retrieval-optimized encoding
    prefixed_query = BGE_QUERY_PREFIX + query
    
    where_clause = None
    if family_filter:
        where_clause = {"family": {"$in": family_filter}}
    
    logger.debug(f"Retrieving top {top_k} controls for query: {query}")
    results = collection.query(
        query_texts=[prefixed_query],
        n_results=top_k,
        where=where_clause,
    )
    
    # Format results
    hits = []
    for i in range(len(results["ids"][0])):
        hits.append({
            "identifier": results["metadatas"][0][i]["identifier"],
            "name": results["metadatas"][0][i]["name"],
            "document": results["documents"][0][i],
            "distance": results["distances"][0][i] if "distances" in results else None,
        })
    
    return hits


def sanity_test():
    """Sanity check: test retrieval on known queries."""
    logger.info("\n" + "=" * 70)
    logger.info("RAG SANITY TEST — BGE Model with Query Prefix")
    logger.info("=" * 70)
    
    test_queries = [
        "patch management for known software vulnerabilities",
        "end of life unsupported software components",
        "detecting and responding to security incidents",
        "monitoring and scanning for vulnerabilities",
        "managing user accounts and privileges",
    ]
    
    for query in test_queries:
        logger.info(f"\nQuery: {query}")
        hits = retrieve_controls(query, top_k=3)
        for hit in hits:
            logger.info(
                f"  [{hit['identifier']}] {hit['name']} "
                f"(distance={hit['distance']:.3f})"
            )


if __name__ == "__main__":
    # Force rebuild to ensure fresh BGE embeddings
    logger.info("Starting fresh build with BGE model...")
    build_index(force_rebuild=True)
    sanity_test()