"""SetuGuard PS1 — Stage 2: RAG-grounded triage report.

CLI: python rag_report.py <feat.json> [-o report.json]
"""
import argparse
import json
import sys
from pathlib import Path

import faiss
import numpy as np
import ollama

from knowledge_base import CHUNKS
from report_prompt import SYSTEM_PROMPT, REPORT_SCHEMA, build_user_prompt

# ============================== SETTINGS ==============================

EMBED_MODEL = "nomic-embed-text"
GEN_MODEL = "mistral"
TOP_K = 4

# ========================================================================


def _build_retrieval_query(features: dict) -> str:
    """Query seed = dangerous perms + suspicious_api categories + mitre ids + string kinds."""
    parts = list(features.get("dangerous_permissions", []))
    parts.extend(sorted({api["category"] for api in features.get("suspicious_apis", [])}))
    parts.extend(sorted({api["mitre"] for api in features.get("suspicious_apis", [])}))
    parts.extend(sorted({s["kind"] for s in features.get("suspicious_strings", [])}))
    if not parts:
        parts = ["benign android application", "no suspicious static indicators"]
    return " ".join(parts)


def _retrieve(query: str, k: int) -> list:
    """Embed CHUNKS + query with nomic-embed-text, cosine-search via FAISS IndexFlatIP.
    Corpus is ~16 chunks, so we build the index in memory on every call — no persistence."""
    texts = [c["text"] for c in CHUNKS]
    corpus_resp = ollama.embed(model=EMBED_MODEL, input=texts)
    corpus_vecs = np.array(corpus_resp.embeddings, dtype="float32")

    query_resp = ollama.embed(model=EMBED_MODEL, input=[query])
    query_vec = np.array(query_resp.embeddings, dtype="float32")

    faiss.normalize_L2(corpus_vecs)
    faiss.normalize_L2(query_vec)

    index = faiss.IndexFlatIP(corpus_vecs.shape[1])
    index.add(corpus_vecs)
    _, idxs = index.search(query_vec, min(k, len(CHUNKS)))

    return [CHUNKS[i] for i in idxs[0] if i != -1]


def generate_report(features: dict) -> dict:
    query = _build_retrieval_query(features)

    try:
        retrieved = _retrieve(query, TOP_K)
    except Exception as e:
        raise RuntimeError(
            f"Embedding/retrieval failed (is 'ollama serve' running with "
            f"'{EMBED_MODEL}' pulled?): {e}"
        ) from e

    user_prompt = build_user_prompt(features, retrieved)

    try:
        resp = ollama.chat(
            model=GEN_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            format=REPORT_SCHEMA,
        )
        model_json = json.loads(resp.message.content)
    except Exception as e:
        raise RuntimeError(
            f"Generation failed (is 'ollama serve' running with '{GEN_MODEL}' pulled?): {e}"
        ) from e

    return {
        **model_json,
        "retrieved_chunk_ids": [c["id"] for c in retrieved],
        "package_name": features["package_name"],
        "sha256": features["sha256"],
    }


def main():
    parser = argparse.ArgumentParser(description="SetuGuard PS1 RAG triage report")
    parser.add_argument("feat_json", help="Path to feature JSON produced by static_analysis.py")
    parser.add_argument("-o", "--output", help="Write report JSON here instead of stdout")
    args = parser.parse_args()

    features = json.loads(Path(args.feat_json).read_text())
    report = generate_report(features)
    output = json.dumps(report, indent=2)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
