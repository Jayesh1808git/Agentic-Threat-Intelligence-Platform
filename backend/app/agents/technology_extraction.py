import logging
import re
from typing import Any

from app.agents.state import CyberRAGState
from app.core.config import settings
from app.schemas.agent_outputs import Asset, TechnologyExtractionResult
from app.services.llm import llm_service

logger = logging.getLogger("technology_extraction_agent")


SYSTEM_PROMPT = """
You are the Technology Extraction Agent in an AI-agent-driven CyberRAG vulnerability assessment workflow.
Your task is to analyze user project input and extract structured technology assets.

The input may contain:
- Natural-language project descriptions (e.g., "Our backend is a Spring Boot 3.2.5 application using PostgreSQL 15 and Redis 7.")
- Structured lists of technologies, dependencies, frameworks, databases, operating systems, cloud services, configuration, or SBOM information.

For each identified technology asset, extract:
- name: The canonical or common name of the technology (e.g., "Spring Boot", "PostgreSQL", "Redis", "Django", "Adobe Campaign")
- vendor: The vendor or developer if known (e.g., "VMware", "PostgreSQL Global Development Group", "Redis Ltd.", "Adobe")
- product: The product identifier if known (e.g., "Spring Boot")
- type: The component type (e.g., "framework", "library", "runtime", "database", "operating_system", "cloud_service", "application")
- version: The exact version string IF explicitly stated in the input (e.g. "3.2.5", "15", "7.4.2").
  CRITICAL: Do NOT invent, assume, or fabricate a version if it is NOT present in the input! If unknown or unstated, set version to null.
- version_constraints: Any version constraint if mentioned (e.g., ">=3.2.0")
- dependency_relationship: "direct", "transitive", or "root"
- criticality: Organizational criticality if specified ("critical", "high", "medium", "low")
- business_impact: Business impact if specified ("high", "medium", "low")

Return structured output matching the TechnologyExtractionResult schema.
"""


_KNOWN_TECHNOLOGIES = (
    ("Spring Boot", r"\bspring[ -]boot\b"),
    ("Kubernetes", r"\b(?:kubernetes|k8s)\b"),
    ("PostgreSQL", r"\bpostgres(?:ql)?\b"),
    ("MongoDB", r"\bmongodb\b"),
    ("FastAPI", r"\bfastapi\b"),
    ("Node.js", r"\bnode(?:\.js)?\b"),
    ("Django", r"\bdjango\b"),
    ("React", r"\breact\b"),
    ("Redis", r"\bredis\b"),
    ("Docker", r"\bdocker\b"),
    ("Python", r"\bpython\b"),
    ("JavaScript", r"\bjavascript\b"),
    ("Java", r"\bjava\b"),
    ("AWS", r"\baws\b|\bamazon web services\b"),
    ("Azure", r"\bazure\b"),
    ("GCP", r"\bgcp\b|\bgoogle cloud\b"),
)


def technology_extraction_agent(state: CyberRAGState) -> dict[str, Any]:
    """
    Agent 1: Technology Extraction Agent

    Combines AI LLM reasoning for natural-language understanding with
    structured input parsing to extract project assets.
    """
    project_input = state.get("project_input", {})
    errors = list(state.get("errors", []))
    extracted_assets: list[Asset] = []

    # 1. Deterministic extraction from structured dictionary fields
    structured_assets = _deduplicate_assets(_extract_from_structured_fields(project_input))
    extracted_assets.extend(structured_assets)

    if structured_assets:
        logger.info("[LLM] agent=technology_extraction completed mode=deterministic")
        return {
            "assets": [a.model_dump(exclude_none=True) for a in structured_assets],
            "errors": errors,
        }

    # 2. AI Reasoning for unstructured / natural language project description
    description_text = _build_description_prompt_text(project_input)

    if description_text and llm_service.is_configured():
        try:
            prompt = f"Extract technologies and explicitly stated versions from this compact project summary:\n\n{description_text}"
            result: TechnologyExtractionResult = llm_service.invoke_structured(
                prompt=prompt,
                response_model=TechnologyExtractionResult,
                system_prompt=SYSTEM_PROMPT,
                model=settings.TECHNOLOGY_EXTRACTION_MODEL,
                agent_name="technology_extraction",
            )

            for asset in result.assets:
                # Enforce no invented versions
                if asset.version and str(asset.version).strip().lower() in ["unknown", "n/a", "none", "null"]:
                    asset.version = None
                extracted_assets.append(asset)

            if not extracted_assets:
                extracted_assets.extend(_extract_from_project_text(project_input))

        except Exception as exc:
            logger.warning("[LLM] technology extraction unavailable; using deterministic parsing")
            extracted_assets.extend(_extract_from_project_text(project_input))
            errors.append("Technology extraction used deterministic fallback.")

    elif not structured_assets:
        extracted_assets.extend(_extract_from_project_text(project_input))
        logger.info("[LLM] agent=technology_extraction completed mode=deterministic")

    # 3. Deduplicate assets
    unique_assets = _deduplicate_assets(extracted_assets)

    return {
        "assets": [a.model_dump(exclude_none=True) for a in unique_assets],
        "errors": errors,
    }


def _build_description_prompt_text(project_input: dict[str, Any]) -> str:
    parts = []
    if project_input.get("name"):
        parts.append(f"Project Name: {str(project_input.get('name'))[:200]}")
    if project_input.get("description"):
        parts.append(f"Description: {str(project_input.get('description'))[:2500]}")

    dependencies = project_input.get("dependencies", [])
    if isinstance(dependencies, dict):
        dependencies = list(dependencies.items())
    if isinstance(dependencies, list):
        compact_dependencies = []
        for dependency in dependencies[:80]:
            if isinstance(dependency, (tuple, list)) and len(dependency) == 2:
                compact_dependencies.append(f"{dependency[0]}:{dependency[1]}")
            elif isinstance(dependency, str):
                compact_dependencies.append(dependency[:160])
            elif isinstance(dependency, dict):
                name = dependency.get("name") or dependency.get("product")
                version = dependency.get("version")
                if name:
                    compact_dependencies.append(f"{name}:{version}" if version else str(name))
        if compact_dependencies:
            parts.append(f"Dependencies: {', '.join(compact_dependencies)}")

    configuration = project_input.get("configuration", {})
    if isinstance(configuration, dict):
        runtime = configuration.get("runtime") or configuration.get("language")
        if runtime:
            parts.append(f"Runtime: {str(runtime)[:200]}")

    return "\n".join(parts)[:4000]


def _extract_from_project_text(project_input: dict[str, Any]) -> list[Asset]:
    text_parts = [str(project_input.get("name", "")), str(project_input.get("description", ""))]
    dependencies = project_input.get("dependencies", [])
    if isinstance(dependencies, dict):
        text_parts.extend(f"{name} {version}" for name, version in list(dependencies.items())[:80])
    elif isinstance(dependencies, list):
        text_parts.extend(str(item) for item in dependencies[:80])
    configuration = project_input.get("configuration", {})
    if isinstance(configuration, dict):
        text_parts.extend(str(configuration.get(key, "")) for key in ("runtime", "language"))
    text = "\n".join(text_parts)[:12000]
    assets: list[Asset] = []

    for name, pattern in _KNOWN_TECHNOLOGIES:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if not match:
            continue
        suffix = text[match.end():].splitlines()[0][:40]
        version_match = re.match(
            r"\s*(?:version\s*)?(?:[:=@]|\s)*v?(\d+(?:\.\d+){0,3})\b",
            suffix,
            flags=re.IGNORECASE,
        )
        assets.append(
            Asset(
                name=name,
                type="technology",
                version=version_match.group(1) if version_match else None,
            )
        )
    return assets


def _extract_from_structured_fields(project_input: dict[str, Any]) -> list[Asset]:
    assets: list[Asset] = []

    # Direct technologies array
    raw_techs = project_input.get("technologies", [])
    if isinstance(raw_techs, list):
        for tech in raw_techs:
            if isinstance(tech, dict):
                assets.append(
                    Asset(
                        name=tech.get("name") or tech.get("product") or "Unknown",
                        vendor=tech.get("vendor"),
                        product=tech.get("product"),
                        type=tech.get("type") or "technology",
                        version=tech.get("version"),
                        criticality=tech.get("criticality"),
                        business_impact=tech.get("business_impact"),
                    )
                )
            elif isinstance(tech, str) and tech.strip():
                assets.append(Asset(name=tech.strip(), type="technology"))

    # Auxiliary list fields
    aux_fields = [
        "languages", "frameworks", "libraries", "dependencies",
        "databases", "operating_systems", "cloud_services", "infrastructure",
    ]
    for field in aux_fields:
        values = project_input.get(field, [])
        if isinstance(values, str):
            values = [values]
        if isinstance(values, list):
            for val in values:
                if isinstance(val, dict):
                    assets.append(
                        Asset(
                            name=val.get("name") or "Unknown",
                            vendor=val.get("vendor"),
                            product=val.get("product"),
                            type=field.rstrip("s"),
                            version=val.get("version"),
                            criticality=val.get("criticality"),
                            business_impact=val.get("business_impact"),
                        )
                    )
                elif isinstance(val, str) and val.strip():
                    assets.append(Asset(name=val.strip(), type=field.rstrip("s")))

    return assets


def _deduplicate_assets(assets: list[Asset]) -> list[Asset]:
    unique: list[Asset] = []
    seen: set[tuple] = set()

    for asset in assets:
        if not asset.name or asset.name == "Unknown":
            continue
        key = (
            asset.name.strip().lower(),
            (asset.type or "").strip().lower(),
            (asset.version or "").strip().lower(),
            (asset.vendor or "").strip().lower(),
        )
        if key not in seen:
            seen.add(key)
            unique.append(asset)

    return unique