"""CLI: python -m evaluation.run_retrieval (from backend/)."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from evaluation.runner import DatasetError, load_dataset, run_evaluation

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATASET = BACKEND_DIR / "evaluation" / "datasets" / "retrieval_golden.json"
RESULTS = BACKEND_DIR / "evaluation" / "results"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate CyberRAG retrieval only; does not call LangGraph or any LLM API.")
    parser.add_argument("--top-k", nargs="+", type=int, default=[5, 10], help="Ranking cutoffs (default: 5 10)")
    parser.add_argument("--category", help="Only evaluate a dataset category, e.g. exact_cve")
    parser.add_argument("--strategy", choices=["hybrid", "lexical", "semantic", "postgresql_fallback"], default=None,
                        help="One strategy; default compares hybrid, lexical, semantic and forced PostgreSQL-only fallback")
    parser.add_argument("--dataset", type=Path, default=DATASET, help="Golden dataset JSON path")
    parser.add_argument("--output-dir", type=Path, default=RESULTS, help="Directory for JSON and Markdown output")
    parser.add_argument("--no-verify-golden", action="store_true", help="Do not verify expected IDs exist in PostgreSQL (not recommended)")
    parser.add_argument("--keep-unlabelled", action="store_true", help="Run but leave queries with null labels unscored; default validation still does this")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        cases = load_dataset(args.dataset, args.category)
    except (OSError, json.JSONDecodeError, DatasetError) as exc:
        print(f"Dataset error: {exc}", file=sys.stderr)
        return 2
    strategies = [args.strategy] if args.strategy else ["hybrid", "lexical", "semantic", "postgresql_fallback"]
    if any(k <= 0 for k in args.top_k):
        print("Every --top-k value must be a positive integer.", file=sys.stderr)
        return 2
    try:
        # Importing postgres is intentionally delayed until the CLI actually runs.
        # It validates POSTGRES_URL in this project and never needs LLM credentials.
        from app.database.postgres import SessionLocal
        db = SessionLocal()
    except Exception as exc:
        print(
            "Database configuration error: retrieval evaluation requires PostgreSQL. "
            "Set POSTGRES_URL in backend/.env (and start/reach the database). "
            "Qdrant should be configured with QDRANT_URL/QDRANT_API_KEY; if unavailable, "
            "the hybrid service may fall back to PostgreSQL lexical results. "
            f"Original error: {type(exc).__name__}: {exc}", file=sys.stderr,
        )
        return 3
    try:
        # Verify connectivity before any results are emitted.
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        rows = run_evaluation(cases, strategies, sorted(set(args.top_k)), args.output_dir, db,
                              verify_golden=not args.no_verify_golden)
    except Exception as exc:
        print(f"Evaluation could not be completed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4
    finally:
        db.close()
    print(f"Evaluation wrote {len(rows)} query-strategy rows to {args.output_dir}")
    failed = sum(bool(row.get("error")) for row in rows)
    unlabelled = sum(not row.get("has_relevant_labels") and not row.get("known_no_relevant") for row in rows)
    print(f"Rows with retrieval errors: {failed}; unlabelled query-strategy rows: {unlabelled}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
