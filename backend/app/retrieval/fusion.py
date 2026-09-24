import re
from typing import Any
from app.models.vulnerability import Vulnerability
from app.retrieval.schemas import NormalizedVulnerabilityResult

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9-]+", re.IGNORECASE)


def rrf_fusion(
    lexical_results: list[tuple[Vulnerability, float]],
    semantic_results: list[tuple[Vulnerability, float]],
    query: str,
    k: int = 60,
    top_k: int = 20,
) -> list[NormalizedVulnerabilityResult]:
    """
    Reciprocal Rank Fusion (RRF) algorithm combining lexical and semantic search results.
    """
    q_lower = query.strip().lower()
    exact_cves = set(CVE_PATTERN.findall(query) + GHSA_PATTERN.findall(query))

    # Map candidate records
    records_by_id: dict[str, Vulnerability] = {}
    lexical_ranks: dict[str, int] = {}
    lexical_scores: dict[str, float] = {}
    semantic_ranks: dict[str, int] = {}
    semantic_scores: dict[str, float] = {}

    for rank, (rec, score) in enumerate(lexical_results, start=1):
        rec_id = str(rec.id)
        records_by_id[rec_id] = rec
        lexical_ranks[rec_id] = rank
        lexical_scores[rec_id] = score

    for rank, (rec, score) in enumerate(semantic_results, start=1):
        rec_id = str(rec.id)
        records_by_id[rec_id] = rec
        semantic_ranks[rec_id] = rank
        semantic_scores[rec_id] = score

    # Compute RRF score
    rrf_scores: dict[str, float] = {}
    max_possible_rrf = (1.0 / (k + 1)) + (1.0 / (k + 1))

    for rec_id in records_by_id:
        lex_rank = lexical_ranks.get(rec_id)
        sem_rank = semantic_ranks.get(rec_id)

        rrf_val = 0.0
        if lex_rank is not None:
            rrf_val += 1.0 / (k + lex_rank)
        if sem_rank is not None:
            rrf_val += 1.0 / (k + sem_rank)

        rrf_scores[rec_id] = rrf_val

    # Normalize RRF scores to 0.0 - 1.0 range
    normalized_results: list[NormalizedVulnerabilityResult] = []

    for rec_id, rec in records_by_id.items():
        base_rrf = rrf_scores[rec_id]
        normalized_score = min(base_rrf / max_possible_rrf, 1.0)

        # Sources
        sources = []
        if rec_id in lexical_ranks:
            sources.append("lexical")
        if rec_id in semantic_ranks:
            sources.append("semantic")

        # Exact match override
        is_exact = False
        if exact_cves:
            rec_cve = (rec.cve or "").lower()
            rec_vid = rec.vulnerability_id.lower()
            for target in exact_cves:
                t_lower = target.lower()
                if rec_cve == t_lower or rec_vid == t_lower:
                    is_exact = True
                    normalized_score = 1.0
                    break

        if not is_exact and (rec.cve and rec.cve.lower() == q_lower):
            is_exact = True
            normalized_score = 1.0

        # Small threat signal adjustment (+0.01 to +0.05) to break ties without distorting query relevance
        signal_boost = 0.0
        if rec.kev:
            signal_boost += 0.02
        if rec.exploit_available:
            signal_boost += 0.01
        if rec.cvss and rec.cvss >= 9.0:
            signal_boost += 0.01

        final_score = round(min(normalized_score + signal_boost, 1.0), 4)

        result_item = NormalizedVulnerabilityResult(
            id=str(rec.id),
            vulnerability_id=rec.vulnerability_id,
            source=rec.source,
            cve=rec.cve,
            title=rec.title or "",
            description=rec.description or "",
            vendor=rec.vendor,
            product=rec.product,
            affected_versions=rec.affected_versions or [],
            patched_versions=rec.patched_versions or [],
            cvss=rec.cvss,
            cvss_vector=rec.cvss_vector,
            epss=rec.epss,
            kev=bool(rec.kev),
            exploit_available=bool(rec.exploit_available),
            references=rec.references or [],
            published=rec.published.isoformat() if rec.published else None,
            updated=rec.updated.isoformat() if rec.updated else None,
            semantic_score=round(semantic_scores[rec_id], 4) if rec_id in semantic_scores else None,
            lexical_score=round(lexical_scores[rec_id], 4) if rec_id in lexical_scores else None,
            final_score=final_score,
            retrieval_sources=sources,
        )
        normalized_results.append(result_item)

    # Sort results by final score descending
    normalized_results.sort(key=lambda x: x.final_score, reverse=True)
    return normalized_results[:top_k]
