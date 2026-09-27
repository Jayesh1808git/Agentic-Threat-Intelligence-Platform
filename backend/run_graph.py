from app.graph import cyberrag_graph


def main():
    # ---------------------------------------------------------
    # Initial CyberRAG State
    # ---------------------------------------------------------
    state = {
        "project_input": {
            "name": "Adobe Campaign Security Assessment",

            # Agent 1 expects structured technology information.
            # Organizational context is included here so that
            # Risk Assessment can consider asset criticality
            # and business impact later in the pipeline.
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
        },

        # -----------------------------------------------------
        # Shared CyberRAG State
        # -----------------------------------------------------
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

    print("=" * 60)
    print("STARTING CYBERRAG LANGGRAPH")
    print("=" * 60)

    # ---------------------------------------------------------
    # Run complete LangGraph pipeline
    # ---------------------------------------------------------
    result = cyberrag_graph.invoke(state)

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