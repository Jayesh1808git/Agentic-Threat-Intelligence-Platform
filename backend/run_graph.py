from app.graph import cyberrag_graph


def build_initial_state(project_input: dict) -> dict:
    """
    Build the initial CyberRAG state expected by LangGraph.
    """

    return {
        "project_input": project_input,

        "assets": [],
        "candidate_vulnerabilities": [],
        "internal_evidence": [],
        "web_evidence": [],
        "validated_findings": [],
        "risk_assessments": [],
        "recommendations": [],
        "report": {},
        "errors": [],
        "citations": [],
    }


def run_cyberrag(project_input: dict) -> dict:
    """
    Run the complete CyberRAG LangGraph pipeline.

    This function is reusable by:
    - FastAPI
    - CLI
    - local testing
    """

    state = build_initial_state(project_input)

    return cyberrag_graph.invoke(state)


def main():
    # ---------------------------------------------------------
    # Example local project input
    # ---------------------------------------------------------
    project_input = {
        "name": "Adobe Campaign Security Assessment",
        "technologies": [
            {
                "name": "Campaign",
                "type": "application",
                "version": "7.4.2",
                "vendor": "adobe",
                "ecosystem": "enterprise",
                "criticality": "critical",
                "business_impact": "high",
            }
        ],
    }

    print("=" * 60)
    print("STARTING CYBERRAG LANGGRAPH")
    print("=" * 60)

    # ---------------------------------------------------------
    # Run complete LangGraph pipeline
    # ---------------------------------------------------------
    result = run_cyberrag(project_input)

    # ---------------------------------------------------------
    # Pipeline Summary
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("CYBERRAG PIPELINE COMPLETED")
    print("=" * 60)

    print("\n[1] Technology Extraction")
    print("Assets:", len(result.get("assets", [])))

    for asset in result.get("assets", []):
        print("  -", asset)

    print("\n[2] Vulnerability Matching")
    print(
        "Candidates:",
        len(result.get("candidate_vulnerabilities", []))
    )

    for candidate in result.get("candidate_vulnerabilities", []):
        print("  -", candidate)

    print("\n[3] Internal Hybrid Retrieval")
    print(
        "Internal Evidence:",
        len(result.get("internal_evidence", []))
    )

    print("\n[4] Conditional Web Search")
    print(
        "Web Evidence:",
        len(result.get("web_evidence", []))
    )

    print("\n[5] Validation")
    print(
        "Validated Findings:",
        len(result.get("validated_findings", []))
    )

    for finding in result.get("validated_findings", []):
        print("  -", finding)

    print("\n[6] Risk Assessment")
    print(
        "Risk Assessments:",
        len(result.get("risk_assessments", []))
    )

    for risk in result.get("risk_assessments", []):
        print("  -", risk)

    print("\n[7] Recommendation")
    print(
        "Recommendations:",
        len(result.get("recommendations", []))
    )

    for recommendation in result.get("recommendations", []):
        print("  -", recommendation)

    print("\n[8] Report")

    report = result.get("report", {})

    print(
        "Report Title:",
        report.get(
            "title",
            "CyberRAG Vulnerability Assessment Report"
        ),
    )

    # ---------------------------------------------------------
    # Errors
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("ERRORS")
    print("=" * 60)

    errors = result.get("errors", [])

    if errors:
        for error in errors:
            print("-", error)
    else:
        print("No errors.")

    # ---------------------------------------------------------
    # Final Report
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("FINAL CYBERRAG REPORT")
    print("=" * 60)

    markdown_report = report.get("markdown")

    if markdown_report:
        print(markdown_report)
    else:
        print("No markdown report generated.")

    print("\n" + "=" * 60)
    print("PIPELINE FINISHED")
    print("=" * 60)


if __name__ == "__main__":
    main()