# Retrieval-only evaluation

This evaluator uses `app.retrieval.service.VulnerabilityRetriever` directly and never runs the LangGraph workflow or imports the internal retrieval agent. It does not invoke Groq, Gemini, OpenAI, RAGAS, or an LLM judge.

## Actual retrieval architecture found in the repository

- `app.retrieval.lexical.LexicalRetriever`: PostgreSQL SQL/ILIKE matching with hand-written token matching scores and exact CVE/GHSA identifier checks. It is **not BM25** and does not use PostgreSQL full-text search.
- `app.retrieval.semantic.SemanticRetriever`: `BAAI/bge-small-en-v1.5` embedding plus Qdrant dense similarity. It hydrates authoritative records from PostgreSQL, first by UUID and then by `(source, vulnerability_id)` payload identity.
- `app.retrieval.fusion.rrf_fusion`: reciprocal-rank fusion, exact CVE/GHSA ranking overrides, then small KEV/exploit/high-CVSS score boosts as tie-breakers.
- `VulnerabilityRetriever.retrieve_with_mode`: calls lexical and semantic retrieval, and when semantic raises returns lexical candidates through the same fusion routine with mode `POSTGRESQL_FALLBACK`. Qdrant connection utility may itself fall back to local persistent Qdrant storage, so `HYBRID` means semantic `.search()` returned without raising, not necessarily that remote Qdrant was used.
- No standalone reranker is present in the inspected retrieval modules. No graph traversal or BM25 implementation is used by the active `VulnerabilityRetriever` path.

## Setup and commands

From `backend/` in the checked-out repository:

```bash
pip install -r requirements.txt
# configure backend/.env with a working PostgreSQL URL:
# POSTGRES_URL=postgresql+psycopg2://USER:PASSWORD@HOST:5432/DATABASE
# QDRANT_URL=https://... (or local http://localhost:6333)
# QDRANT_API_KEY=... (if required)
pytest -q tests/test_retrieval_metrics.py tests/test_retrieval_evaluation.py
python -m evaluation.run_retrieval --top-k 5 10
python -m evaluation.run_retrieval --category exact_cve --strategy hybrid
python -m evaluation.run_retrieval --strategy lexical
python -m evaluation.run_retrieval --strategy semantic
python -m evaluation.run_retrieval --strategy postgresql_fallback
```

No LLM credentials are required. PostgreSQL must be reachable for a real evaluation; Qdrant must be populated with vectors for meaningful semantic/hybrid evaluation. `POSTGRES_URL` is required by the repository's existing `app.database.postgres` module. Keep credentials in your ignored local `.env`; do not commit them.

## Golden labels and verification

`datasets/retrieval_golden.json` intentionally distinguishes:

- `manual_candidate_unverified`: a human-proposed label that still must be checked against the actual local database and candidate pool;
- `manual_negative_unverified`: a proposed negative that must be verified against the local database;
- `needs_manual_label`: an unlabelled case with `expected_relevant_ids: null`. It is run only for diagnostics and all relevance metrics remain null.

By default, the CLI checks all non-null expected IDs against PostgreSQL before retrieval. It exits before scoring if an identifier is missing. This is not enough to prove a label complete: exact ID presence is a necessary check, while the relevant set and negative cases still require human relevance judgments. Edit the dataset locally after reviewing actual database contents. Never treat the candidate Log4j labels as database-verified until this command has passed and labels have been reviewed.

Set `--no-verify-golden` only for debugging the runner; it does not turn unverified labels into trusted ground truth.

## Metrics conventions

- Retrieval IDs are stable CVE/vulnerability identifiers; UUIDs are retained separately for database hydration diagnostics. If a result lacks both identifiers, its UUID fallback is used.
- Duplicates are removed by first occurrence, so they occupy one rank.
- Precision@K is relevant unique results in the first K divided by K, even if fewer than K are returned.
- Missing labels (`null`) are invalid for relevance metrics and are reported unscored; an explicit `[]` is a known-negative query. For `[]`, Hit Rate/Precision are 0; Recall/MRR/nDCG are undefined (`null`) and excluded from their aggregate means.
- Recall is the number of relevant IDs retrieved divided by the complete known relevant set.
- MRR is reciprocal rank of the first relevant item, or 0 if none is retrieved.
- nDCG uses binary gain for list labels and graded gains for `{ "ID": gain }` mapping inputs.
- Failed strategy/query executions carry an `error`; they are not assigned synthetic ranking metrics. Compare only the same successfully evaluated query IDs when doing external analyses.

## Result files

Each run writes to `evaluation/results/`:

- `retrieval_results.json`: query/strategy details, expected labels, ranked IDs, component/final scores where exposed, mode, elapsed time, errors, exact-ID success and UUID resolvability.
- `retrieval_summary.json`: aggregate relevance and reliability measures by strategy, cutoff and category.
- `retrieval_report.md`: a human-readable summary with metric conventions.

Generated results are runtime outputs and should be reviewed before committing. Unit tests use mocked objects and do not need live databases or network access. Live end-to-end checks need local PostgreSQL/Qdrant and a manually judged golden set.

## Known comparison limits

The forced `postgresql_fallback` strategy directly exercises the existing lexical PostgreSQL component through existing fusion, while `hybrid` invokes the production `retrieve_with_mode`. `lexical` and `semantic` expose the existing components independently by passing their results through `rrf_fusion` as a single populated list. This gives the same output schema, but scores from those single-component runs are fusion-normalized scores, not the raw lexical/semantic component scores; the raw values are retained in each ranking. The production hybrid path is unchanged. There is no independent post-reranker strategy because no separate reranker exists in the active service.
