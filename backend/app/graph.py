from langgraph.graph import StateGraph, START, END

from app.agents.state import CyberRAGState
from app.agents.technology_extraction import technology_extraction_agent
from app.agents.vulnerability_matching import vulnerability_matching_agent
from app.agents.internal_retrieval import internal_hybrid_retrieval_agent
from app.agents.web_search import web_search_agent
from app.agents.validation import validation_agent
from app.agents.risk_assessment import risk_assessment_agent
from app.agents.recommendation import recommendation_agent
from app.agents.report import report_agent


def evidence_decision(state: CyberRAGState) -> str:
    internal_evidence = state.get("internal_evidence", [])

    # No internal evidence → use Web Search
    if not internal_evidence:
        return "web_search"

    # Check whether important information is missing
    for evidence in internal_evidence:

        # Missing patch/fixed-version information
        if not evidence.get("patched_versions"):
            return "web_search"

        # Unknown exploit status
        if evidence.get("exploit_available") is None:
            return "web_search"

    # Internal evidence is sufficiently complete
    return "validation"


def build_cyberrag_graph():

    graph = StateGraph(CyberRAGState)

    # Agents
    graph.add_node(
        "technology_extraction",
        technology_extraction_agent
    )

    graph.add_node(
        "vulnerability_matching",
        vulnerability_matching_agent
    )

    graph.add_node(
        "internal_retrieval",
        internal_hybrid_retrieval_agent
    )

    graph.add_node(
        "web_search",
        web_search_agent
    )

    graph.add_node(
        "validation",
        validation_agent
    )

    graph.add_node(
        "risk_assessment",
        risk_assessment_agent
    )

    graph.add_node(
        "recommendation",
        recommendation_agent
    )

    graph.add_node(
        "report",
        report_agent
    )

    # Main pipeline
    graph.add_edge(
        START,
        "technology_extraction"
    )

    graph.add_edge(
        "technology_extraction",
        "vulnerability_matching"
    )

    graph.add_edge(
        "vulnerability_matching",
        "internal_retrieval"
    )

    # Conditional Web Search
    graph.add_conditional_edges(
        "internal_retrieval",
        evidence_decision,
        {
            "web_search": "web_search",
            "validation": "validation",
        },
    )

    graph.add_edge(
        "web_search",
        "validation"
    )

    graph.add_edge(
        "validation",
        "risk_assessment"
    )

    graph.add_edge(
        "risk_assessment",
        "recommendation"
    )

    graph.add_edge(
        "recommendation",
        "report"
    )

    graph.add_edge(
        "report",
        END
    )

    return graph.compile()


cyberrag_graph = build_cyberrag_graph()