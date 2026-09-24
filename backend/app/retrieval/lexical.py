import re
from typing import Any
from sqlalchemy import or_, select, and_
from sqlalchemy.orm import Session

from app.models.vulnerability import Vulnerability
from app.retrieval.schemas import RetrievalFilters

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9-]+", re.IGNORECASE)


class LexicalRetriever:
    """
    PostgreSQL-based structured and lexical retrieval.
    """

    def __init__(self, db: Session):
        self.db = db

    def search(
        self,
        query: str,
        filters: RetrievalFilters | None = None,
        limit: int = 20,
    ) -> list[tuple[Vulnerability, float]]:
        if not query or not query.strip():
            return []

        q = query.strip()
        q_lower = q.lower()

        cve_matches = CVE_PATTERN.findall(q)
        ghsa_matches = GHSA_PATTERN.findall(q)

        exact_ids = set(cve_matches + ghsa_matches)

        base_conditions = []

        # Apply user filters
        if filters:
            if filters.vendor:
                base_conditions.append(Vulnerability.vendor.ilike(f"%{filters.vendor}%"))
            if filters.product:
                base_conditions.append(Vulnerability.product.ilike(f"%{filters.product}%"))
            if filters.severity is not None:
                base_conditions.append(Vulnerability.cvss >= filters.severity)
            if filters.source:
                base_conditions.append(Vulnerability.source.ilike(filters.source))
            if filters.kev is not None:
                base_conditions.append(Vulnerability.kev == filters.kev)
            if filters.exploit_available is not None:
                base_conditions.append(Vulnerability.exploit_available == filters.exploit_available)

        # 1. Exact ID match check
        exact_results: list[tuple[Vulnerability, float]] = []
        if exact_ids:
            for target_id in exact_ids:
                stmt = select(Vulnerability).where(
                    or_(
                        Vulnerability.cve.ilike(target_id),
                        Vulnerability.vulnerability_id.ilike(target_id),
                    ),
                    *base_conditions
                ).limit(5)
                for rec in self.db.scalars(stmt).all():
                    score = 1.0 if (rec.cve and rec.cve.lower() == target_id.lower()) else 0.95
                    exact_results.append((rec, score))

        # 2. General SQL search
        keywords = [k for k in re.split(r"\s+", q_lower) if len(k) > 1]
        search_conditions = []

        for kw in keywords[:5]: # Top 5 tokens
            search_conditions.append(
                or_(
                    Vulnerability.cve.ilike(f"%{kw}%"),
                    Vulnerability.vulnerability_id.ilike(f"%{kw}%"),
                    Vulnerability.vendor.ilike(f"%{kw}%"),
                    Vulnerability.product.ilike(f"%{kw}%"),
                    Vulnerability.title.ilike(f"%{kw}%"),
                    Vulnerability.description.ilike(f"%{kw}%"),
                )
            )

        if search_conditions:
            statement = (
                select(Vulnerability)
                .where(and_(*base_conditions, or_(*search_conditions)))
                .limit(limit * 2)
            )
            candidates = self.db.scalars(statement).all()
        else:
            candidates = []

        # Score candidates
        scored_dict: dict[str, tuple[Vulnerability, float]] = {}

        # Put exact matches first
        for rec, score in exact_results:
            scored_dict[str(rec.id)] = (rec, score)

        for rec in candidates:
            rec_id = str(rec.id)
            if rec_id in scored_dict:
                continue

            # Calculate match quality
            score = 0.3 # base match
            title_lower = (rec.title or "").lower()
            desc_lower = (rec.description or "").lower()
            vendor_lower = (rec.vendor or "").lower()
            product_lower = (rec.product or "").lower()
            cve_lower = (rec.cve or "").lower()

            if q_lower in cve_lower or q_lower in rec.vulnerability_id.lower():
                score = 0.95
            elif q_lower in product_lower or q_lower in vendor_lower:
                score = 0.85
            elif q_lower in title_lower:
                score = 0.75
            elif q_lower in desc_lower:
                score = 0.50
            else:
                # Token match count
                matches = sum(1 for kw in keywords if kw in title_lower or kw in desc_lower or kw in product_lower)
                score = min(0.40 + (matches * 0.10), 0.75)

            scored_dict[rec_id] = (rec, score)

        # Return sorted by lexical score descending
        results = sorted(scored_dict.values(), key=lambda x: x[1], reverse=True)
        return results[:limit]
