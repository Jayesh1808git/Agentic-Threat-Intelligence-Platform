"""Aggregate retrieval results and render deterministic JSON/Markdown reports."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

METRICS = ("hit_rate", "recall", "precision", "mrr", "ndcg")


def _mean_defined(rows: list[dict[str, Any]], key: str) -> float | None:
    values = [float(row[key]) for row in rows if row.get(key) is not None]
    return mean(values) if values else None


def summarize_results(rows: list[dict[str, Any]], top_ks: list[int]) -> dict[str, Any]:
    strategies = sorted({str(row.get("strategy", "hybrid")) for row in rows})
    summary: dict[str, Any] = {
        "status": "completed" if rows and not all(row.get("error") for row in rows) else "failed_or_empty",
        "query_count": len({row.get("query_id") for row in rows}),
        "result_rows": len(rows),
        "strategies": {},
        "conventions": {
            "deduplication": "Keep first occurrence of each retrieved ID.",
            "precision_at_k": "Divide by K, including unreturned positions when fewer than K results exist.",
            "unlabelled": "Missing expected_relevant_ids is an error; no-label results are not silently treated as zero.",
            "empty_ground_truth": "A known empty relevant set is excluded from Recall/MRR/nDCG aggregates and shown separately.",
        },
    }
    for strategy in strategies:
        subset = [r for r in rows if r.get("strategy", "hybrid") == strategy]
        strategy_summary: dict[str, Any] = {
            "query_count": len({r.get("query_id") for r in subset}),
            "queries_with_results": sum(bool(r.get("retrieved_ids")) for r in subset),
            "queries_with_relevant_result": {},
            "empty_result_rate": (sum(not r.get("retrieved_ids") for r in subset) / len(subset)) if subset else None,
            "average_latency_ms": mean([r["latency_ms"] for r in subset if isinstance(r.get("latency_ms"), (int, float))]) if any(isinstance(r.get("latency_ms"), (int, float)) for r in subset) else None,
            "error_count": sum(bool(r.get("error")) for r in subset),
            "mode_counts": {},
            "exact_identifier": {"query_count": 0, "success_count": 0, "success_rate": None},
            "postgres_resolution": {"checked_count": 0, "resolved_count": 0, "resolution_rate": None},
            "by_k": {},
            "by_category": {},
        }
        for row in subset:
            mode = row.get("retrieval_mode") or "UNKNOWN"
            strategy_summary["mode_counts"][mode] = strategy_summary["mode_counts"].get(mode, 0) + 1
            if row.get("is_exact_identifier"):
                strategy_summary["exact_identifier"]["query_count"] += 1
                if row.get("exact_identifier_success") is True:
                    strategy_summary["exact_identifier"]["success_count"] += 1
            if row.get("postgres_resolution_checked"):
                strategy_summary["postgres_resolution"]["checked_count"] += 1
                if row.get("postgres_ids_resolved") is True:
                    strategy_summary["postgres_resolution"]["resolved_count"] += 1
        exact = strategy_summary["exact_identifier"]
        if exact["query_count"]:
            exact["success_rate"] = exact["success_count"] / exact["query_count"]
        resolution = strategy_summary["postgres_resolution"]
        if resolution["checked_count"]:
            resolution["resolution_rate"] = resolution["resolved_count"] / resolution["checked_count"]

        for k in top_ks:
            k_rows = [r for r in subset if str(k) in r.get("metrics", {})]
            metrics = {metric: _mean_defined([r["metrics"][str(k)] for r in k_rows], metric) for metric in METRICS}
            metrics["labelled_query_count"] = sum(r.get("has_relevant_labels", False) for r in k_rows)
            metrics["known_no_relevant_count"] = sum(r.get("known_no_relevant", False) for r in k_rows)
            strategy_summary["by_k"][str(k)] = metrics

        categories = sorted({str(r.get("category", "uncategorized")) for r in subset})
        for category in categories:
            category_rows = [r for r in subset if r.get("category", "uncategorized") == category]
            strategy_summary["by_category"][category] = {
                "query_count": len({r.get("query_id") for r in category_rows}),
                "by_k": {
                    str(k): {metric: _mean_defined([r["metrics"][str(k)] for r in category_rows if str(k) in r.get("metrics", {})], metric) for metric in METRICS}
                    for k in top_ks
                },
            }
        for k in top_ks:
            k_rows = [r for r in subset if str(k) in r.get("metrics", {})]
            strategy_summary["queries_with_relevant_result"][str(k)] = sum(
                any(r["metrics"][str(k)].get(metric) == 1.0 for metric in ("hit_rate",)) and r.get("has_relevant_labels", False)
                for r in k_rows
            )
        summary["strategies"][strategy] = strategy_summary
    return summary


def write_reports(rows: list[dict[str, Any]], top_ks: list[int], output_dir: str | Path) -> dict[str, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    summary = summarize_results(rows, top_ks)
    results_path = output / "retrieval_results.json"
    summary_path = output / "retrieval_summary.json"
    report_path = output / "retrieval_report.md"
    results_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [
        "# CyberRAG Retrieval Evaluation Report", "",
        f"- Status: **{summary['status']}**", f"- Result rows: {summary['result_rows']}",
        f"- Unique queries: {summary['query_count']}", "",
        "> This report is generated from the current run. Failed/skipped strategies are not assigned scores.", "",
    ]
    for strategy, data in summary["strategies"].items():
        lines += [f"## Strategy: `{strategy}`", "", f"- Errors: {data['error_count']}",
                  f"- Empty-result rate: {_fmt(data['empty_result_rate'])}",
                  f"- Average latency: {_fmt(data['average_latency_ms'])} ms",
                  f"- Retrieval modes: `{json.dumps(data['mode_counts'], sort_keys=True)}`", "",
                  "| K | Hit Rate | Recall | Precision | MRR | nDCG | Labelled queries | Known no-relevant |",
                  "|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for k, metrics in data["by_k"].items():
            lines.append(f"| {k} | {_fmt(metrics['hit_rate'])} | {_fmt(metrics['recall'])} | {_fmt(metrics['precision'])} | {_fmt(metrics['mrr'])} | {_fmt(metrics['ndcg'])} | {metrics['labelled_query_count']} | {metrics['known_no_relevant_count']} |")
        lines += ["", "### Per-category ranking metrics", "", "| Category | K | Hit Rate | Recall | Precision | MRR | nDCG |", "|---|---:|---:|---:|---:|---:|---:|"]
        for cat, catdata in data["by_category"].items():
            for k, metrics in catdata["by_k"].items():
                lines.append(f"| {cat} | {k} | {_fmt(metrics['hit_rate'])} | {_fmt(metrics['recall'])} | {_fmt(metrics['precision'])} | {_fmt(metrics['mrr'])} | {_fmt(metrics['ndcg'])} |")
        lines += ["", "### Reliability", "", f"- Exact-identifier success: {_fmt(data['exact_identifier']['success_rate'])} ({data['exact_identifier']['success_count']}/{data['exact_identifier']['query_count']})",
                  f"- PostgreSQL identifier resolution: {_fmt(data['postgres_resolution']['resolution_rate'])} ({data['postgres_resolution']['resolved_count']}/{data['postgres_resolution']['checked_count']} checked)", ""]
    lines += ["## Metric conventions", "", "- Retrieved IDs are de-duplicated by keeping their first rank.",
              "- Precision@K divides by K even when fewer than K records are returned.",
              "- Queries with a missing relevance label are invalid and recorded as errors.",
              "- Queries with a verified empty relevant set are treated as known negatives; Recall, MRR and nDCG are undefined and excluded from those metric means.",
              "- nDCG uses binary gain for list/set labels or graded gains for `{id: gain}` labels.", ""]
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return {"results": results_path, "summary": summary_path, "report": report_path}


def _fmt(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)
