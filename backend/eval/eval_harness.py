#!/usr/bin/env python3
"""
CyberRAG evaluation harness.

  python eval_harness.py assessment --data eval_data --predictor live  [--repeats 1] [--limit N]
  python eval_harness.py retrieval  --data eval_data --predictor live
  python eval_harness.py extraction --data eval_data --predictor live
  python eval_harness.py <suite>    --predictor mock     # offline self-test of the harness itself

Predictors
  live : imports your code (run from anywhere; --backend points at the backend/ dir)
  http : POST to a running API (--base-url http://localhost:8000)  [assessment only]
  mock : oracle + injected noise, used only to prove the metrics code works

Ablations (set env BEFORE running, run the suite once per setting):
  LLM_ENABLED=false         -> deterministic-only pipeline vs LLM-assisted
  retrieval --mode lexical|semantic|hybrid
"""
import argparse, json, math, os, statistics, sys, time
from collections import defaultdict
from pathlib import Path


def load_jsonl(p): return [json.loads(l) for l in open(p) if l.strip()]
def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
            "tp": tp, "fp": fp, "fn": fn}
def pct(xs, q):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None
def norm(s): return "".join(ch for ch in str(s).lower() if ch.isalnum())

# =============================================================================
# ASSESSMENT
# =============================================================================
def get_assess_predictor(args, corpus):
    if args.predictor == "live":
        sys.path.insert(0, args.backend); os.chdir(args.backend)
        from run_graph import run_cyberrag
        return lambda pi: run_cyberrag(pi)
    if args.predictor == "http":
        import requests
        def f(pi):
            r = requests.post(f"{args.base_url}/api/v1/assessment", json={"project_input": pi}, timeout=300)
            r.raise_for_status(); d = r.json()
            return {"validated_findings": d["findings"], "report": d["report"], "errors": d["errors"],
                    "retrieval_mode": d["retrieval_mode"], "llm_metadata": {k: d.get(k) for k in
                    ("llm_call_count", "rate_limit_count", "retry_count", "fallback_count", "fallback_used")}}
        return f
    if args.predictor == "naive":                    # baseline: product-name match, ignores version
        def f(pi):
            fnd = []
            for t in pi["technologies"]:
                for vid, v in corpus.items():
                    if v.get("product") and norm(v["product"]) == norm(t["name"]):
                        fnd.append({"asset": {"name": t["name"]}, "vulnerability_id": vid, "status": "validated",
                                    "affected": True, "evidence": [{"x": 1}]})
            return {"validated_findings": fnd, "errors": [], "retrieval_mode": "NAIVE", "llm_metadata": {}}
        return f
    import random; rnd = random.Random(0)           # mock: truth + 8% flips + 3% hallucination
    case_lookup = {}
    def f(pi):
        c = case_lookup[pi["name"]]; fnd = []
        for key, lab in c["gold"]["labels"].items():
            vid = key.split("|")[1]
            if rnd.random() < 0.08: lab = not lab
            fnd.append({"asset": {"name": key.split("|")[0]}, "vulnerability_id": vid, "status": "validated" if lab else "not_affected",
                        "affected": lab, "confidence": 0.9, "cvss": corpus.get(vid, {}).get("cvss"),
                        "evidence": [{"x": 1}], "sources": ["NVD"]})
        if rnd.random() < 0.03: fnd.append({"asset": {"name": "x"}, "vulnerability_id": "CVE-9999-0000", "status": "validated", "affected": True, "evidence": []})
        return {"validated_findings": fnd, "risk_assessments": [], "errors": [], "retrieval_mode": "HYBRID", "llm_metadata": {}}
    f.case_lookup = case_lookup
    return f


def run_assessment(args):
    cases = load_jsonl(Path(args.data) / "assessment_eval.jsonl")
    if args.limit:                                   # stratified, deterministic subset
        import random; rnd = random.Random(7); groups = defaultdict(list)
        for c in cases: groups[c["case_type"]].append(c)
        sub = []
        for g in groups.values():
            rnd.shuffle(g); sub += g[: max(1, round(args.limit * len(g) / len(cases)))]
        cases = sub
    corpus = json.load(open(Path(args.data) / "corpus_index.json"))
    predict = get_assess_predictor(args, corpus)
    if hasattr(predict, "case_lookup"): predict.case_lookup.update({c["project_input"]["name"]: c for c in cases})

    od0 = Path(args.out); od0.mkdir(exist_ok=True, parents=True)
    cache_path = od0 / "raw_cache.jsonl"; cache = {}
    if cache_path.exists():
        for l in open(cache_path):
            r = json.loads(l); cache[r["key"]] = r["res"]
    cache_f = open(cache_path, "a")
    pair = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "review": 0})
    tot = lambda k: pair["__all__"][k]
    per_case, latencies, llm_calls, rate_limits, errors, fallback_cases = [], [], [], [], 0, 0
    exact, flips, hallucinated, uncited, fp_audit, status_counts = 0, 0, 0, 0, [], defaultdict(int)
    n_findings = 0; unrelated_clean = unrelated_total = 0

    for c in cases:
        runs = []
        for rep in range(args.repeats):
            key = f"{c['case_id']}#{rep}"
            if key in cache:
                res = cache[key]
            else:
                t0 = time.time()
                try: res = predict(c["project_input"])
                except Exception as e: res = {"validated_findings": [], "errors": [str(e)]}; errors += 1
                res["_latency"] = time.time() - t0
                cache_f.write(json.dumps({"key": key, "res": res}, default=str) + "\n"); cache_f.flush()
                if args.sleep: time.sleep(args.sleep)
            latencies.append(res.get("_latency", 0.0))
            md = res.get("llm_metadata") or {}
            llm_calls.append(md.get("llm_call_count") or 0); rate_limits.append(md.get("rate_limit_count") or 0)
            fallback_cases += bool(md.get("fallback_used"))
            runs.append(res)
        res = runs[0]
        findings = res.get("validated_findings", [])
        labels = {k: v for k, v in c["gold"]["labels"].items()}
        gold_pos_ids = set(c["gold"]["expected_positive_ids"])
        pred_pos, pred_review, pred_neg = set(), set(), set()
        for f in findings:
            vid = f.get("vulnerability_id") or f.get("vulnerability"); n_findings += 1
            status_counts[f.get("status")] += 1
            if vid not in corpus: hallucinated += 1
            if f.get("status") == "validated" and not (f.get("evidence") or f.get("references") or f.get("sources")): uncited += 1
            (pred_pos if f.get("status") == "validated" and f.get("affected") is not False else
             pred_review if f.get("status") == "needs_review" else pred_neg).add(vid)
        # repeat stability
        if args.repeats > 1:
            sets = [frozenset((x.get("vulnerability_id") or x.get("vulnerability")) for x in r.get("validated_findings", []) if x.get("status") == "validated") for r in runs]
            flips += len(set(sets)) > 1

        ctype = c["case_type"]
        if ctype == "unrelated":
            unrelated_total += 1; unrelated_clean += (len(pred_pos) == 0)
        for key, lab in labels.items():
            vid = key.split("|")[1]; bucket = [pair["__all__"], pair[ctype]]
            if c.get("version_relation"): bucket.append(pair[f"rel:{c['version_relation']}"])
            for b in bucket:
                if vid in pred_review: b["review"] += 1
                if lab and vid in pred_pos: b["tp"] += 1
                elif lab: b["fn"] += 1
                elif vid in pred_pos: b["fp"] += 1
                else: b["tn"] += 1
        # strict: validated findings with no gold label at all (possible FP -> audit manually)
        for vid in pred_pos:
            if gold_pos_ids and vid in gold_pos_ids: continue
            if not any(k.endswith("|" + vid) for k in labels):
                fp_audit.append({"case_id": c["case_id"], "vuln_id": vid, "assets": [t["name"] for t in c["project_input"]["technologies"]],
                                 "version": [t.get("version") for t in c["project_input"]["technologies"]]})
        ok = pred_pos == gold_pos_ids; exact += ok
        per_case.append({"case_id": c["case_id"], "type": ctype, "exact": ok, "missed": sorted(gold_pos_ids - pred_pos),
                         "wrong": sorted(pred_pos - gold_pos_ids)})

    summary = {}
    for k, b in pair.items():
        d = prf(b["tp"], b["fp"], b["fn"])
        n = b["tp"] + b["fp"] + b["fn"] + b["tn"]
        d.update({"decision_accuracy": round((b["tp"] + b["tn"]) / n, 4) if n else None, "needs_review_rate": round(b["review"] / n, 4) if n else None,
                  "fpr": round(b["fp"] / (b["fp"] + b["tn"]), 4) if b["fp"] + b["tn"] else None, "n_pairs": n})
        summary[k] = d
    overall = summary.pop("__all__")
    overall["precision_strict (unlabeled validated findings counted as FP)"] = round(
        overall["tp"] / (overall["tp"] + overall["fp"] + len(fp_audit)), 4) if overall["tp"] + overall["fp"] + len(fp_audit) else 0.0
    out = {"suite": "assessment", "n_cases": len(cases), "overall": overall,
           "by_case_type": {k: v for k, v in summary.items() if not k.startswith("rel:")},
           "by_version_relation": {k[4:]: v for k, v in summary.items() if k.startswith("rel:")},
           "case_exact_match_rate": round(exact / len(cases), 4),
           "unrelated_specificity (no validated finding)": round(unrelated_clean / unrelated_total, 4) if unrelated_total else None,
           "unlabeled_validated_findings (audit these)": len(fp_audit),
           "hallucinated_vuln_id_rate": round(hallucinated / max(n_findings, 1), 4),
           "validated_without_evidence_rate": round(uncited / max(n_findings, 1), 4),
           "status_distribution": dict(status_counts),
           "run_stability_flip_rate": round(flips / len(cases), 4) if args.repeats > 1 else "n/a (use --repeats 3)",
           "ops": {"latency_p50_s": round(statistics.median(latencies), 2), "latency_p95_s": round(pct(latencies, .95), 2),
                   "avg_llm_calls": round(statistics.mean(llm_calls), 2), "rate_limit_events": sum(rate_limits),
                   "pipeline_errors": errors, "fallback_runs": fallback_cases}}
    od = Path(args.out); od.mkdir(exist_ok=True, parents=True)
    json.dump(out, open(od / "assessment_results.json", "w"), indent=2)
    json.dump(per_case, open(od / "assessment_per_case.json", "w"), indent=1)
    with open(od / "fp_audit.jsonl", "w") as f:
        for r in fp_audit: f.write(json.dumps(r) + "\n")
    return out

# =============================================================================
# RETRIEVAL
# =============================================================================
def run_retrieval(args):
    qs = load_jsonl(Path(args.data) / "retrieval_eval.jsonl")
    if args.limit: qs = qs[: args.limit]
    corpus = json.load(open(Path(args.data) / "corpus_index.json"))
    ids = list(corpus)
    if args.predictor == "live":
        sys.path.insert(0, args.backend); os.chdir(args.backend)
        from app.database.postgres import SessionLocal
        from app.retrieval.service import VulnerabilityRetriever
        from app.retrieval.lexical import LexicalRetriever
        from app.retrieval.semantic import SemanticRetriever
        from app.retrieval.schemas import RetrievalFilters
        db = SessionLocal(); R = VulnerabilityRetriever(db)
        def search(q, k):
            if args.mode == "lexical": res = R.lexical_retriever.search(query=q, filters=RetrievalFilters(), limit=k)
            elif args.mode == "semantic": res = R.semantic_retriever.search(query=q, filters=RetrievalFilters(), limit=k)
            else: res = R.retrieve(query=q, limit=k)
            return [getattr(r, "vulnerability_id", None) or r["vulnerability_id"] for r in res]
    else:
        import random; rnd = random.Random(1)
        relmap = {q["query"]: q["relevant"] for q in qs}
        def search(q, k):
            r = list(relmap[q]); out = [x for x in r if rnd.random() > .2]; out += rnd.sample(ids, 20)
            rnd.shuffle(out[:5]); return out[:k]
    Ks = [1, 5, 10, 20]; by = defaultdict(lambda: defaultdict(list)); lat = []
    for q in qs:
        rel = set(q["relevant"]); t0 = time.time()
        try: got = search(q["query"], 20)
        except Exception: got = []
        lat.append(time.time() - t0)
        m = by[q["qtype"]]
        for k in Ks:
            m[f"recall@{k}"].append(len(rel & set(got[:k])) / len(rel) if rel else 0)
            m[f"hit@{k}"].append(float(bool(rel & set(got[:k]))))
        rr = next((1 / (i + 1) for i, x in enumerate(got) if x in rel), 0); m["mrr"].append(rr)
        dcg = sum(1 / math.log2(i + 2) for i, x in enumerate(got[:10]) if x in rel)
        idcg = sum(1 / math.log2(i + 2) for i in range(min(len(rel), 10))); m["ndcg@10"].append(dcg / idcg if idcg else 0)
    out = {"suite": "retrieval", "mode": args.mode,
           "by_query_type": {t: {k: round(statistics.mean(v), 4) for k, v in m.items()} | {"n": len(m["mrr"])} for t, m in by.items()},
           "latency_p50_s": round(statistics.median(lat), 3), "latency_p95_s": round(pct(lat, .95), 3)}
    od = Path(args.out); od.mkdir(exist_ok=True, parents=True)
    json.dump(out, open(od / f"retrieval_results_{args.mode}.json", "w"), indent=2); return out

# =============================================================================
# EXTRACTION
# =============================================================================
def run_extraction(args):
    cs = load_jsonl(Path(args.data) / "extraction_eval.jsonl")
    if args.predictor == "live":
        sys.path.insert(0, args.backend); os.chdir(args.backend)
        from app.agents.technology_extraction import technology_extraction_agent
        predict = lambda pi: technology_extraction_agent({"project_input": pi, "errors": []}).get("assets", [])
    else:
        predict = lambda pi: []
        mock = {c["project_input"]["name"]: c for c in cs}
        predict = lambda pi: [{"name": a["name"], "version": a["version"]} for a in mock[pi["name"]]["gold_assets"][:-1]]
    agg = defaultdict(lambda: [0, 0, 0, 0])      # tp_name, fp_name, fn_name, version_correct
    for c in cs:
        pred = predict(c["project_input"]); P = {norm(a.get("name")): str(a.get("version") or "") for a in pred}
        G = {norm(a["name"]): a["version"] for a in c["gold_assets"]}
        for style in (c["style"], "__all__"):
            a = agg[style]; a[0] += len(set(P) & set(G)); a[1] += len(set(P) - set(G)); a[2] += len(set(G) - set(P))
            a[3] += sum(1 for n in set(P) & set(G) if P[n] == G[n])
    out = {"suite": "extraction", "by_style": {s: prf(a[0], a[1], a[2]) | {"version_accuracy_on_matched": round(a[3] / a[0], 4) if a[0] else None} for s, a in agg.items()}}
    od = Path(args.out); od.mkdir(exist_ok=True, parents=True)
    json.dump(out, open(od / "extraction_results.json", "w"), indent=2); return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("suite", choices=["assessment", "retrieval", "extraction"])
    ap.add_argument("--data", default="eval_data"); ap.add_argument("--out", default="eval_results")
    ap.add_argument("--predictor", choices=["live", "http", "mock", "naive"], default="live")
    ap.add_argument("--backend", default=str(Path("../backend").resolve()))
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--mode", choices=["hybrid", "lexical", "semantic"], default="hybrid")
    ap.add_argument("--sleep", type=float, default=0, help="seconds between cases (rate limits)")
    ap.add_argument("--repeats", type=int, default=1); ap.add_argument("--limit", type=int)
    a = ap.parse_args()
    res = {"assessment": run_assessment, "retrieval": run_retrieval, "extraction": run_extraction}[a.suite](a)
    print(json.dumps(res, indent=2))