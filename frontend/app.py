"""CyberRAG – Streamlit frontend.

Talks to the FastAPI backend described in docs/frontend-guide.md:
  POST /api/v1/assessment   (synchronous, no job id)
  GET  /retrieval/search    (hybrid vulnerability search)
  GET  /health/

Run:  streamlit run app.py
"""

from __future__ import annotations

import json
import math
import os
from datetime import datetime
from typing import Any

import pandas as pd
import requests
import streamlit as st

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
DEFAULT_API_URL = os.getenv("CYBERRAG_API_URL", "http://localhost:8000")

TECH_TYPES = ["technology", "framework", "library", "runtime", "database", "application", "os"]
CRITICALITY = ["critical", "high", "medium", "low"]
IMPACT = ["high", "medium", "low"]
TECH_COLUMNS = ["name", "type", "version", "vendor", "ecosystem", "criticality", "business_impact"]

RISK_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "minimal": "⚪"}
RISK_ORDER = ["critical", "high", "medium", "low", "minimal"]
STATUS_LABEL = {
    "completed": ("✅", "Completed"),
    "partial": ("⚠️", "Partial"),
    "failed": ("❌", "Failed"),
}

EXAMPLE_TECH = pd.DataFrame(
    [
        {"name": "Spring Boot", "type": "framework", "version": "3.2.5", "vendor": "VMware",
         "ecosystem": "Maven", "criticality": "high", "business_impact": "high"},
        {"name": "PostgreSQL", "type": "database", "version": "15.4", "vendor": "PostgreSQL",
         "ecosystem": None, "criticality": "high", "business_impact": "high"},
        {"name": "Log4j", "type": "library", "version": "2.14.1", "vendor": "Apache",
         "ecosystem": "Maven", "criticality": "medium", "business_impact": "medium"},
    ],
    columns=TECH_COLUMNS,
)

st.set_page_config(page_title="CyberRAG", page_icon="🛡️", layout="wide")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _blank(v: Any) -> bool:
    if v is None:
        return True
    if isinstance(v, float) and math.isnan(v):
        return True
    return isinstance(v, str) and not v.strip()


def fmt_num(v: Any, digits: int = 1) -> str:
    return "—" if v is None else f"{v:.{digits}f}"


def fmt_pct(v: Any) -> str:
    return "—" if v is None else f"{v * 100:.1f}%"


def asset_label(asset: Any) -> str:
    if isinstance(asset, dict):
        name = asset.get("name") or "unknown"
        ver = asset.get("version")
        return f"{name} {ver}" if ver else name
    return str(asset) if asset else "unknown"


def finding_id(f: dict) -> str:
    return f.get("vulnerability") or f.get("vulnerability_id") or f.get("cve") or "unknown"


def safe_links(urls: list[Any]) -> list[str]:
    """Only http(s) URLs become clickable – blocks javascript:/data: schemes."""
    return [u for u in urls if isinstance(u, str) and u.lower().startswith(("http://", "https://"))]


def tri_bool(label: str) -> bool | None:
    return {"Any": None, "Yes": True, "No": False}[label]


def format_api_error(resp: requests.Response) -> str:
    """Turn a FastAPI error body into something a human can act on."""
    try:
        detail = resp.json().get("detail")
    except ValueError:
        return f"HTTP {resp.status_code}"
    if isinstance(detail, list):  # pydantic validation errors
        parts = []
        for e in detail:
            loc = ".".join(str(p) for p in e.get("loc", []) if p != "body")
            parts.append(f"**{loc}**: {e.get('msg', 'invalid')}" if loc else e.get("msg", "invalid"))
        return "\n".join(f"- {p}" for p in parts)
    return str(detail) if detail else f"HTTP {resp.status_code}"


@st.cache_data(ttl=15, show_spinner=False)
def check_health(base_url: str) -> tuple[bool, str]:
    try:
        r = requests.get(f"{base_url}/health/", timeout=4)
        r.raise_for_status()
        return True, r.json().get("service", "CyberRAG")
    except requests.RequestException as exc:
        return False, type(exc).__name__


def clean_technologies(df: pd.DataFrame) -> tuple[list[dict], list[str]]:
    """Returns (technologies payload, validation errors)."""
    techs, errors = [], []
    for i, row in df.reset_index(drop=True).iterrows():
        rec = {c: (str(row[c]).strip() if not _blank(row.get(c)) else None) for c in TECH_COLUMNS}
        if all(v is None for v in rec.values()):
            continue  # fully empty row
        if rec["name"] is None:
            errors.append(f"Row {i + 1}: technology name is required.")
            continue
        techs.append({k: v for k, v in rec.items() if v is not None})
    return techs, errors


# --------------------------------------------------------------------------- #
# API calls
# --------------------------------------------------------------------------- #
def run_assessment(base_url: str, project_input: dict, timeout: int) -> dict:
    resp = requests.post(
        f"{base_url}/api/v1/assessment",
        json={"project_input": project_input},
        timeout=timeout,
    )
    if resp.status_code == 400:
        raise ValueError(format_api_error(resp))
    if resp.status_code >= 500:
        # Keep raw detail for diagnostics only; never present it as guidance.
        st.session_state.last_error_raw = resp.text[:4000]
        raise RuntimeError("The assessment workflow failed on the server.")
    resp.raise_for_status()
    return resp.json()


def run_search(base_url: str, params: dict) -> dict:
    resp = requests.get(f"{base_url}/retrieval/search", params=params, timeout=60)
    if resp.status_code in (400, 422):
        raise ValueError(format_api_error(resp))
    resp.raise_for_status()
    return resp.json()


# --------------------------------------------------------------------------- #
# Rendering: findings / risk / recommendations
# --------------------------------------------------------------------------- #
def findings_frame(findings: list[dict]) -> pd.DataFrame:
    rows = [
        {
            "CVE": finding_id(f),
            "Asset": asset_label(f.get("asset")),
            "CVSS": f.get("cvss"),
            "EPSS": f.get("epss"),
            "KEV": bool(f.get("kev")),
            "Exploit": bool(f.get("exploit_available")),
            "Confidence": f.get("confidence"),
            "Fixed in": ", ".join(f.get("patched_versions") or []) or "—",
        }
        for f in findings
    ]
    return pd.DataFrame(rows)


def render_findings(findings: list[dict], empty_msg: str, needs_review: bool = False) -> None:
    if not findings:
        st.info(empty_msg)
        return

    findings = sorted(findings, key=lambda f: (f.get("cvss") is None, -(f.get("cvss") or 0)))
    st.dataframe(
        findings_frame(findings),
        hide_index=True,
        width="stretch",
        column_config={
            "CVSS": st.column_config.NumberColumn(format="%.1f"),
            "EPSS": st.column_config.NumberColumn(format="%.3f", help="Exploit prediction probability (0–1)"),
            "KEV": st.column_config.CheckboxColumn(help="On CISA Known Exploited Vulnerabilities list"),
            "Exploit": st.column_config.CheckboxColumn(help="Public exploit available"),
            "Confidence": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.2f"),
        },
    )

    for f in findings:
        flags = ("🔥 KEV " if f.get("kev") else "") + ("💣 Exploit " if f.get("exploit_available") else "")
        title = f"{finding_id(f)} · {asset_label(f.get('asset'))}  —  CVSS {fmt_num(f.get('cvss'))} {flags}"
        with st.expander(title):
            if needs_review:
                st.warning(
                    "Needs manual review: the pipeline could not make a deterministic "
                    "affected / not-affected decision (often because the installed version is unknown)."
                )
            if f.get("reason"):
                st.markdown(f"**Why:** {f['reason']}")

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("CVSS", fmt_num(f.get("cvss")))
            c2.metric("EPSS", fmt_pct(f.get("epss")))
            c3.metric("Confidence", fmt_pct(f.get("confidence")))
            c4.metric("Version match", {True: "Yes", False: "No", None: "Unknown"}[f.get("version_match")])

            if f.get("cvss_vector"):
                st.code(f["cvss_vector"], language=None)

            v1, v2 = st.columns(2)
            v1.markdown("**Affected versions**")
            v1.write(", ".join(f.get("affected_versions") or []) or "—")
            v2.markdown("**Patched versions**")
            v2.write(", ".join(f.get("patched_versions") or []) or "—")

            checks = {
                "Identity match": f.get("identity_match"),
                "Product match": f.get("product_match"),
                "Source corroborated": f.get("source_corroborated"),
            }
            st.caption("  ·  ".join(f"{k}: {'✅' if v else '❌'}" for k, v in checks.items()))

            for label, key in (("Discrepancies", "discrepancies"), ("Conflicts", "conflicts")):
                if f.get(key):
                    st.markdown(f"**{label}**")
                    for item in f[key]:
                        st.markdown(f"- {item}")

            sources = safe_links(f.get("sources") or [])
            if sources:
                st.markdown("**Sources**")
                for u in sources:
                    st.markdown(f"- {u}")

            if f.get("evidence"):
                with st.expander(f"Evidence ({len(f['evidence'])})"):
                    st.json(f["evidence"], expanded=False)


def render_risk(risks: list[dict], recs: list[dict]) -> None:
    if not risks and not recs:
        st.info("No risk assessments or recommendations were returned – typically this means no finding qualified for scoring.")
        return

    if risks:
        st.subheader("Risk assessments")
        risks = sorted(risks, key=lambda r: -(r.get("risk_score") or 0))
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "CVE": r.get("vulnerability_id"),
                        "Asset": asset_label(r.get("asset")),
                        "Level": f"{RISK_ICON.get(r.get('risk_level'), '')} {r.get('risk_level', '—')}",
                        "Score": r.get("risk_score"),
                    }
                    for r in risks
                ]
            ),
            hide_index=True,
            width="stretch",
            column_config={"Score": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f")},
        )
        for r in risks:
            lvl = r.get("risk_level", "—")
            with st.expander(f"{RISK_ICON.get(lvl, '')} {r.get('vulnerability_id')} · {asset_label(r.get('asset'))} — {fmt_num(r.get('risk_score'), 0)}/100 ({lvl})"):
                st.markdown(r.get("rationale") or "_No rationale provided._")
                if r.get("risk_factors"):
                    st.markdown("**Risk factors**")
                    st.json(r["risk_factors"], expanded=False)
                if r.get("scoring_formula"):
                    st.markdown("**Scoring formula**")
                    st.json(r["scoring_formula"], expanded=False)

    if recs:
        st.subheader("Remediation recommendations")
        prio_rank = {"critical": 0, "urgent": 0, "high": 1, "medium": 2, "low": 3}
        recs = sorted(recs, key=lambda r: prio_rank.get(str((r.get("recommendation") or {}).get("priority", "")).lower(), 9))
        for r in recs:
            body = r.get("recommendation") or {}
            prio = str(body.get("priority", "—"))
            with st.expander(f"[{prio.upper()}] {r.get('vulnerability_id')} · {r.get('asset')} — {body.get('action', 'Remediate')}"):
                if body.get("target_version"):
                    st.markdown(f"**Target version:** `{body['target_version']}`")
                if body.get("description"):
                    st.markdown(body["description"])
                if body.get("mitigation"):
                    st.markdown(f"**Mitigation / workaround:** {body['mitigation']}")
                refs = safe_links(r.get("references") or [])
                if refs:
                    st.markdown("**References**")
                    for u in refs:
                        st.markdown(f"- {u}")


def render_results(res: dict) -> None:
    report = res.get("report") or {}
    findings = res.get("findings") or []
    status = res.get("status", "completed")
    icon, label = STATUS_LABEL.get(status, ("ℹ️", status))

    confirmed = report.get("confirmed_vulnerabilities") or []
    potential = report.get("potential_vulnerabilities") or []
    not_app = report.get("not_applicable") or []
    risks = report.get("risk_assessments") or []
    recs = report.get("recommendations") or []

    # ---- banners -------------------------------------------------------- #
    if status == "failed":
        st.error("The assessment failed and produced no usable report.")
    elif status == "partial":
        st.warning(
            "Partial result: hybrid retrieval was unavailable, so the run used the PostgreSQL fallback. "
            "Coverage may be lower than usual."
        )
    if res.get("fallback_used"):
        st.info(f"LLM fallback was used (reason: `{res.get('fallback_reason') or 'unspecified'}`). "
                "Results are still deterministic and valid; narrative text may be simpler.")
    if res.get("errors"):
        with st.expander(f"⚠️ {len(res['errors'])} workflow warning(s)"):
            for e in res["errors"]:
                st.markdown(f"- {e}")

    # ---- headline metrics ---------------------------------------------- #
    top = max((r.get("risk_score") or 0 for r in risks), default=None)
    m = st.columns(6)
    m[0].metric("Status", f"{icon} {label}")
    m[1].metric("Retrieval", res.get("retrieval_mode", "—"))
    m[2].metric("Confirmed", len(confirmed))
    m[3].metric("Needs review", len(potential))
    m[4].metric("Not affected", len(not_app))
    m[5].metric("Top risk score", "—" if top is None else f"{top:.0f}/100")

    tabs = st.tabs([
        "Overview",
        f"Confirmed ({len(confirmed)})",
        f"Needs review ({len(potential)})",
        f"Not affected ({len(not_app)})",
        f"Risk & fixes ({len(risks)})",
        "Report",
        "Diagnostics",
    ])

    with tabs[0]:
        st.subheader(report.get("title") or f"Assessment – {res.get('project_name')}")
        if report.get("generated_at"):
            st.caption(f"Generated {report['generated_at']}")
        st.markdown(report.get("executive_summary") or "_No executive summary returned._")

        if risks:
            counts = pd.Series([str(r.get("risk_level", "")).lower() for r in risks]).value_counts()
            dist = pd.DataFrame({"findings": [int(counts.get(l, 0)) for l in RISK_ORDER]}, index=RISK_ORDER)
            st.markdown("**Risk level distribution**")
            st.bar_chart(dist, height=220)

        assets = report.get("affected_assets") or []
        if assets:
            st.markdown("**Assets evaluated**")
            st.dataframe(pd.DataFrame(assets), hide_index=True, width="stretch")

    with tabs[1]:
        render_findings(confirmed, "No confirmed vulnerabilities for the submitted stack. 🎉")
    with tabs[2]:
        render_findings(potential, "Nothing needs manual review.", needs_review=True)
    with tabs[3]:
        render_findings(not_app, "No findings were ruled out.")
    with tabs[4]:
        render_risk(risks, recs)

    with tabs[5]:
        md = report.get("markdown") or ""
        if md:
            d1, d2, _ = st.columns([1, 1, 4])
            stamp = datetime.now().strftime("%Y%m%d-%H%M")
            slug = "".join(c if c.isalnum() else "-" for c in (res.get("project_name") or "report")).strip("-").lower()
            d1.download_button("⬇ Markdown", md, f"{slug}-{stamp}.md", "text/markdown")
            d2.download_button("⬇ JSON", json.dumps(res, indent=2), f"{slug}-{stamp}.json", "application/json")
            st.divider()
            # unsafe_allow_html is off by default → raw HTML in LLM output is not rendered
            st.markdown(md)
        else:
            st.info("No Markdown report was returned.")

    with tabs[6]:
        st.caption("Operational metadata only – these values say nothing about vulnerability severity.")
        d = st.columns(6)
        d[0].metric("LLM used", "Yes" if res.get("llm_used") else "No")
        d[1].metric("LLM calls", res.get("llm_call_count", 0))
        d[2].metric("Rate limits (429)", res.get("rate_limit_count", 0))
        d[3].metric("Retries", res.get("retry_count", 0))
        d[4].metric("Fallbacks", res.get("fallback_count", 0))
        d[5].metric("Findings returned", len(findings))
        with st.expander("Raw response"):
            st.json(res, expanded=False)


# --------------------------------------------------------------------------- #
# Session state
# --------------------------------------------------------------------------- #
ss = st.session_state
ss.setdefault("tech_df", pd.DataFrame(columns=TECH_COLUMNS))
ss.setdefault("editor_ver", 0)
ss.setdefault("result", None)
ss.setdefault("search_result", None)
ss.setdefault("pending", False)       # assessment in flight
ss.setdefault("last_error_raw", None)
ss.setdefault("assess_error", None)   # {"msg": str, "raw": str|None}


def _start_assessment() -> None:
    ss.pending = True


def _load_example() -> None:
    ss.tech_df = EXAMPLE_TECH.copy()
    ss.editor_ver += 1
    ss.form_name = "Payments API"
    ss.form_desc = "Customer payment service"


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.title("🛡️ CyberRAG")
    st.caption("Agentic threat intelligence")
    api_url = st.text_input("Backend URL", DEFAULT_API_URL).rstrip("/")
    timeout = st.slider("Assessment timeout (s)", 30, 900, 300, 30,
                        help="The assessment runs synchronously and can take a while with LLM calls.")
    ok, info = check_health(api_url)
    if ok:
        st.success(f"Connected · {info}")
    else:
        st.error(f"Backend unreachable ({info})")
    if st.button("Re-check", width="stretch"):
        check_health.clear()
        st.rerun()
    st.divider()
    st.caption("Health only confirms the API process is up, not Postgres / Qdrant / Neo4j.")

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
tab_assess, tab_search = st.tabs(["🔍 Assessment", "📚 Vulnerability search"])

# ============================ Assessment ================================== #
with tab_assess:
    st.header("Assess your stack")
    st.write("Describe a project and its technologies. Exact names and versions give the most reliable results; "
             "unknown versions come back as *needs review* rather than a yes/no answer.")

    busy = ss.pending
    left, right = st.columns([2, 1])
    with left:
        name = st.text_input("Project name *", key="form_name", placeholder="Payments API", disabled=busy)
    with right:
        st.write("")
        st.write("")
        st.button("Load example", on_click=_load_example, disabled=busy)

    desc = st.text_area("Description (optional)", key="form_desc", height=80, disabled=busy,
                        placeholder="Free-text context, e.g. 'Internet-facing REST service running on Kubernetes'.")

    st.markdown("**Technologies**")
    edited = st.data_editor(
        ss.tech_df,
        key=f"tech_editor_{ss.editor_ver}",
        num_rows="dynamic",
        width="stretch",
        disabled=busy,
        column_config={
            "name": st.column_config.TextColumn("Name *", help="Component or product name", required=False),
            "type": st.column_config.SelectboxColumn("Type", options=TECH_TYPES),
            "version": st.column_config.TextColumn("Version", help="Exact installed version. Don't guess."),
            "vendor": st.column_config.TextColumn("Vendor"),
            "ecosystem": st.column_config.TextColumn("Ecosystem", help="e.g. Maven, npm, PyPI"),
            "criticality": st.column_config.SelectboxColumn("Criticality", options=CRITICALITY),
            "business_impact": st.column_config.SelectboxColumn("Business impact", options=IMPACT),
        },
    )

    techs, tech_errors = clean_technologies(edited)
    has_input = bool(techs) or bool((desc or "").strip())
    problems = list(tech_errors)
    if not (name or "").strip():
        problems.append("Project name is required.")
    if not has_input:
        problems.append("Add at least one technology or a description.")

    for p in problems:
        st.caption(f"⚠️ {p}")

    st.button(
        "Running…" if busy else "Run assessment",
        type="primary",
        on_click=_start_assessment,
        disabled=busy or bool(problems) or not ok,
        help=None if ok else "Backend is unreachable.",
    )

    if busy:
        payload = {"name": name.strip()}
        if (desc or "").strip():
            payload["description"] = desc.strip()
        if techs:
            payload["technologies"] = techs
        ss.last_error_raw = None
        ss.assess_error = None
        try:
            with st.spinner("Running the multi-agent pipeline – extraction → retrieval → validation → risk → report. "
                            "This can take a few minutes."):
                ss.result = run_assessment(api_url, payload, timeout)
        except ValueError as exc:
            ss.result = None
            ss.assess_error = {"msg": f"The backend rejected the input:\n\n{exc}", "raw": None}
        except requests.Timeout:
            ss.result = None
            ss.assess_error = {"msg": f"No response within {timeout}s. The assessment may still be running server-side – "
                                      "raise the timeout in the sidebar and retry.", "raw": None}
        except requests.ConnectionError:
            ss.result = None
            ss.assess_error = {"msg": "Couldn't reach the backend. Check the URL in the sidebar and that uvicorn is running.",
                               "raw": None}
        except RuntimeError as exc:
            ss.result = None
            ss.assess_error = {"msg": f"{exc} You can retry; your input has been kept.", "raw": ss.last_error_raw}
        except requests.RequestException as exc:
            ss.result = None
            ss.assess_error = {"msg": f"Unexpected HTTP error: {exc}", "raw": None}
        finally:
            ss.pending = False
        st.rerun()  # always re-render so the form is re-enabled, success or failure

    if ss.assess_error:
        st.error(ss.assess_error["msg"])
        if ss.assess_error["raw"]:
            with st.expander("Developer diagnostics (raw server response)"):
                st.code(ss.assess_error["raw"], language="json")

    if ss.result:
        st.divider()
        render_results(ss.result)

# ============================== Search ==================================== #
with tab_search:
    st.header("Search the vulnerability knowledge base")
    st.caption("Hybrid lexical + semantic search with rank fusion. Accepts CVE IDs, product names, or natural language.")

    with st.form("search_form"):
        q = st.text_input("Query *", placeholder="Spring Boot  ·  CVE-2024-22243  ·  remote code execution in log4j")
        c1, c2, c3 = st.columns(3)
        vendor = c1.text_input("Vendor")
        product = c2.text_input("Product")
        source = c3.text_input("Source", placeholder="NVD, CISA, GITHUB")
        c4, c5, c6, c7 = st.columns(4)
        min_cvss = c4.number_input("Min CVSS", 0.0, 10.0, 0.0, 0.5)
        kev = c5.selectbox("CISA KEV", ["Any", "Yes", "No"])
        exploit = c6.selectbox("Public exploit", ["Any", "Yes", "No"])
        limit = c7.number_input("Max results", 1, 100, 20)
        go = st.form_submit_button("Search", type="primary")

    if go:
        if not q.strip():
            st.warning("Enter a query.")
        else:
            params: dict[str, Any] = {"q": q.strip(), "limit": int(limit)}
            for k, v in (("vendor", vendor), ("product", product), ("source", source)):
                if v.strip():
                    params[k] = v.strip()
            if min_cvss > 0:
                params["severity"] = min_cvss
            for k, v in (("kev", tri_bool(kev)), ("exploit_available", tri_bool(exploit))):
                if v is not None:
                    params[k] = str(v).lower()
            try:
                with st.spinner("Searching…"):
                    ss.search_result = run_search(api_url, params)
            except ValueError as exc:
                ss.search_result = None
                st.error("Invalid search parameters:")
                st.markdown(str(exc))
            except requests.ConnectionError:
                ss.search_result = None
                st.error("Couldn't reach the backend.")
            except requests.RequestException as exc:
                ss.search_result = None
                st.error(f"Search failed: {exc}")

    sr = ss.search_result
    if sr:
        results = sr.get("results") or []
        st.markdown(f"**{sr.get('total', len(results))} result(s)** for `{sr.get('query')}`")
        if results:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "ID": r.get("cve") or r.get("vulnerability_id"),
                            "Title": r.get("title"),
                            "Vendor": r.get("vendor"),
                            "Product": r.get("product"),
                            "CVSS": r.get("cvss"),
                            "EPSS": r.get("epss"),
                            "KEV": bool(r.get("kev")),
                            "Exploit": bool(r.get("exploit_available")),
                            "Source": r.get("source"),
                            "Match": r.get("final_score"),
                        }
                        for r in results
                    ]
                ),
                hide_index=True,
                width="stretch",
                column_config={
                    "CVSS": st.column_config.NumberColumn(format="%.1f"),
                    "EPSS": st.column_config.NumberColumn(format="%.3f"),
                    "Match": st.column_config.ProgressColumn(
                        min_value=0, max_value=max(1.0, max(r.get("final_score") or 0 for r in results)),
                        format="%.3f", help="Retrieval relevance – not a risk score.",
                    ),
                },
            )
            for r in results:
                with st.expander(f"{r.get('cve') or r.get('vulnerability_id')} — {r.get('title') or ''}"):
                    st.write(r.get("description") or "_No description._")
                    a, b = st.columns(2)
                    a.markdown("**Affected versions**")
                    a.write(", ".join(r.get("affected_versions") or []) or "—")
                    b.markdown("**Patched versions**")
                    b.write(", ".join(r.get("patched_versions") or []) or "—")
                    st.caption(
                        f"Published: {r.get('published') or '—'} · Updated: {r.get('updated') or '—'} · "
                        f"Retrieved via: {', '.join(r.get('retrieval_sources') or []) or '—'}"
                    )
                    if r.get("cvss_vector"):
                        st.code(r["cvss_vector"], language=None)
                    for u in safe_links(r.get("references") or [])[:10]:
                        st.markdown(f"- {u}")
