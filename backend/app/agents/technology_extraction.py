from typing import Any

from app.agents.state import CyberRAGState


def technology_extraction_agent(state: CyberRAGState) -> dict[str, Any]:
    """
    Agent 1: Technology Extraction

    Extracts technology assets from the user's project input.

    This agent identifies technologies and their available metadata.
    It does NOT decide whether a technology is vulnerable.
    """

    project_input = state.get("project_input", {})

    assets: list[dict[str, Any]] = []

    # ---------------------------------------------------------
    # Structured technologies
    # ---------------------------------------------------------

    technologies = project_input.get("technologies", [])

    if isinstance(technologies, list):
        for technology in technologies:

            if isinstance(technology, dict):

                asset = {
                    "name": technology.get("name"),
                    "type": technology.get("type"),
                    "version": technology.get("version"),
                    "vendor": technology.get("vendor"),
                    "ecosystem": technology.get("ecosystem"),

                    # Organizational context, when provided by the user
                    "criticality": technology.get("criticality"),
                    "business_impact": technology.get("business_impact"),
                }

                # Remove empty values.
                asset = {
                    key: value
                    for key, value in asset.items()
                    if value is not None and value != ""
                }

                if asset:
                    assets.append(asset)

            elif isinstance(technology, str) and technology.strip():

                assets.append(
                    {
                        "name": technology.strip(),
                        "type": "technology",
                    }
                )

    # ---------------------------------------------------------
    # Common structured project fields
    # ---------------------------------------------------------

    technology_fields = [
        "languages",
        "frameworks",
        "libraries",
        "dependencies",
        "databases",
        "operating_systems",
        "cloud_services",
        "infrastructure",
    ]

    for field in technology_fields:

        values = project_input.get(field, [])

        if isinstance(values, str):
            values = [values]

        if not isinstance(values, list):
            continue

        for value in values:

            if isinstance(value, dict):

                asset = {
                    "name": value.get("name"),
                    "type": field.rstrip("s"),
                    "version": value.get("version"),
                    "vendor": value.get("vendor"),

                    # Optional organizational context
                    "criticality": value.get("criticality"),
                    "business_impact": value.get("business_impact"),
                }

                asset = {
                    key: item
                    for key, item in asset.items()
                    if item is not None and item != ""
                }

                if asset:
                    assets.append(asset)

            elif isinstance(value, str) and value.strip():

                assets.append(
                    {
                        "name": value.strip(),
                        "type": field.rstrip("s"),
                    }
                )

    # ---------------------------------------------------------
    # Remove duplicate assets
    # ---------------------------------------------------------

    unique_assets: list[dict[str, Any]] = []
    seen: set[tuple] = set()

    for asset in assets:

        identity = (
            asset.get("name"),
            asset.get("type"),
            asset.get("version"),
            asset.get("vendor"),
        )

        if identity not in seen:
            seen.add(identity)
            unique_assets.append(asset)

    return {
        "assets": unique_assets,
        "errors": state.get("errors", []),
    }