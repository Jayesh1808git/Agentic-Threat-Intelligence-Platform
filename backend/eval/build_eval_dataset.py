#!/usr/bin/env python3
"""
Build a ground-truth evaluation dataset for CyberRAG from your own vulnerability
corpus (the seed CSV or the live `vulnerabilities` table).

Ground truth is produced by an INDEPENDENT oracle (own version-range parser, no
imports from the CyberRAG codebase), so the dataset does not inherit bugs from
validation.py. LLMs are never used to create labels.

Outputs (in --out):
  corpus_index.json       id -> {product, vendor, affected, patched, cvss, epss, kev}
  assessment_eval.jsonl   project-level cases + per-(asset, vuln) gold labels
  retrieval_eval.jsonl    queries + relevant vuln ids
  extraction_eval.jsonl   project text/dependency input + gold (name, version) assets
  dataset_stats.json      counts per case type

Usage:
  python build_eval_dataset.py --csv ../data/vuln_seed_data.csv --out eval_data
  python build_eval_dataset.py --db-url postgresql://user:pw@host/db --out eval_data
"""
import argparse, ast, json, random, re
from collections import defaultdict
from pathlib import Path

import pandas as pd
from packaging.version import InvalidVersion, Version

# ----------------------------------------------------------------------------
# Independent version oracle
# ----------------------------------------------------------------------------
CLAUSE = re.compile(r"^\s*(<=|>=|==|=|<|>)?\s*v?([0-9][0-9A-Za-z.\-+_]*)\s*$")


def pv(s):
    try:
        return Version(str(s).strip().lstrip("v"))
    except InvalidVersion:
        return None


def in_one_range(v: Version, rng: str):
    """AND of comma-separated clauses. Returns True/False/None(unparseable)."""
    rng = rng.strip()
    if rng in ("", "*"):
        return None
    for clause in rng.split(","):
        m = CLAUSE.match(clause)
        if not m:
            return None
        op, ver = m.group(1) or "=", pv(m.group(2))
        if ver is None:
            return None
        ok = {"<": v < ver, "<=": v <= ver, ">": v > ver, ">=": v >= ver,
              "=": v == ver, "==": v == ver}[op]
        if not ok:
            return False
    return True


def oracle_affected(version: str, ranges: list[str]):
    """True / False / None (cannot be decided -> excluded from gold)."""
    v = pv(version)
    if v is None or not ranges:
        return None
    results = [in_one_range(v, r) for r in ranges]
    if any(r is True for r in results):
        return True
    if any(r is None for r in results):
        return None
    return False


def bound_versions(ranges):
    out = []
    for r in ranges:
        for clause in r.split(","):
            m = CLAUSE.match(clause)
            if m and pv(m.group(2)):
                out.append((m.group(1) or "=", m.group(2)))
    return out


def candidate_versions(ranges):
    """Mutations around every bound: at-bound, +/-1 patch, +/-1 minor, +/-1 major."""
    cands = {}
    for op, raw in bound_versions(ranges):
        v = pv(raw)
        if v is None or v.is_prerelease or v.is_devrelease or len(v.release) > 4 or len(raw) > 14:
            continue
        rel = list(v.release) + [0] * (3 - len(v.release))
        M, m, p = rel[:3]
        muts = {raw: "at_bound", f"{M}.{m}.{p + 1}": "bound_plus_patch",
                f"{M}.{m + 1}.0": "bound_plus_minor", f"{M + 1}.0.0": "bound_plus_major"}
        if p > 0: muts[f"{M}.{m}.{p - 1}"] = "bound_minus_patch"
        if m > 0: muts[f"{M}.{m - 1}.{p}"] = "bound_minus_minor"
        if M > 0: muts[f"{M - 1}.{m}.{p}"] = "bound_minus_major"
        for s, tag in muts.items():
            cands.setdefault(s, tag)
    return cands


# ----------------------------------------------------------------------------
# Corpus loading
# ----------------------------------------------------------------------------
def jl(x):
    if isinstance(x, list): return x
    if x is None or (isinstance(x, float) and pd.isna(x)): return []
    s = str(x).strip()
    if not s or s == "[]": return []
    try: return json.loads(s)
    except Exception:
        try: return ast.literal_eval(s)
        except Exception: return [s]


def load_corpus(args):
    if args.db_url:
        from sqlalchemy import create_engine
        df = pd.read_sql(f"SELECT * FROM {args.table}", create_engine(args.db_url))
    else:
        df = pd.read_csv(args.csv)
    rows = []
    for r in df.to_dict("records"):
        rows.append({
            "vuln_id": r["vulnerability_id"], "cve": r.get("cve") if pd.notna(r.get("cve")) else None,
            "source": r.get("source"),
            "vendor": (r.get("vendor") if pd.notna(r.get("vendor")) else None),
            "product": (r.get("product") if pd.notna(r.get("product")) else None),
            "title": r.get("title") or "", "description": r.get("description") or "",
            "affected": [str(a) for a in jl(r.get("affected_versions"))],
            "patched": [str(a) for a in jl(r.get("patched_versions"))],
            "cvss": None if pd.isna(r.get("cvss")) else float(r["cvss"]),
            "epss": None if pd.isna(r.get("epss")) else float(r["epss"]),
            "kev": bool(r.get("kev")) if pd.notna(r.get("kev")) else False,
        })
    return rows


# ----------------------------------------------------------------------------
# Name aliasing (simulate how real SBOMs / humans write package names)
# ----------------------------------------------------------------------------
def aliases(product: str):
    out = set()
    p = product.strip()
    if "/" in p:
        parts = [x for x in p.split("/") if x and not re.fullmatch(r"v\d+", x)]
        if parts: out.add(parts[-1])
    if ":" in p: out.add(p.split(":")[-1])
    if re.search(r"[-_]", p):
        out.add(re.sub(r"[-_]", " ", p).title())
        out.add(p.replace("-", "_") if "-" in p else p.replace("_", "-"))
    out.add(p.upper() if len(p) <= 8 else p.title())
    out.discard(p)
    return sorted(out)


UNRELATED = [("numpy", "1.26.4"), ("pandas", "2.2.1"), ("react", "18.2.0"), ("lodash", "4.17.21"),
             ("redis-py", "5.0.1"), ("pytest", "8.1.1"), ("black", "24.3.0"), ("tailwindcss", "3.4.1"),
             ("uvicorn", "0.29.0"), ("celery", "5.3.6"), ("jest", "29.7.0"), ("eslint", "8.57.0"),
             ("typescript", "5.4.2"), ("prometheus", "2.51.0"), ("grafana", "10.4.1"), ("kafka", "3.7.0"),
             ("rabbitmq", "3.13.0"), ("nginx", "1.25.4"), ("terraform", "1.7.5"), ("sqlalchemy", "2.0.29")]


def mask(text, product, vendor):
    t = re.sub(r"CVE-\d{4}-\d{4,}", "this issue", text)
    for token in filter(None, [product, vendor]):
        t = re.sub(re.escape(token), "the product", t, flags=re.I)
    return t


# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="data/vuln_seed_data.csv")
    ap.add_argument("--db-url"); ap.add_argument("--table", default="vulnerabilities")
    ap.add_argument("--out", default="eval_data")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-mixed", type=int, default=40, help="multi-asset projects")
    ap.add_argument("--n-retrieval-desc", type=int, default=150)
    args = ap.parse_args()
    rnd = random.Random(args.seed)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    rows = load_corpus(args)
    by_id = {r["vuln_id"]: r for r in rows}
    by_product = defaultdict(list)
    for r in rows:
        if r["product"] and r["affected"]:
            by_product[r["product"].lower()].append(r)

    all_text = " ".join((r["title"] + " " + r["description"] + " " + (r["product"] or "")).lower() for r in rows)

    # ---------------- single-asset assessment cases ----------------
    cases, case_id = [], 0

    def gold_for(product_key, version):
        labels = {}
        for r in by_product[product_key]:
            lab = oracle_affected(version, r["affected"])
            if lab is not None:
                labels[r["vuln_id"]] = lab
        return labels

    def mk_asset(name, version, row):
        a = {"name": name, "version": version, "type": "library"}
        if row.get("vendor"): a["vendor"] = row["vendor"]
        return a

    pool = []  # (product_key, version, tag, labels)
    for pk, group in by_product.items():
        ranges = sorted({a for r in group for a in r["affected"]})
        for ver, tag in candidate_versions(ranges).items():
            labels = gold_for(pk, ver)
            if not labels:
                continue
            pool.append((pk, ver, tag, labels))

    # stratify: positive vs negative decision, bounded per product to avoid domination
    per_prod = defaultdict(list)
    for item in pool: per_prod[item[0]].append(item)
    singles = []
    for pk, items in per_prod.items():
        rnd.shuffle(items)
        pos = [i for i in items if any(i[3].values())]
        neg = [i for i in items if not any(i[3].values())]
        singles += pos[:3] + neg[:3]

    for pk, ver, tag, labels in singles:
        row = by_product[pk][0]
        name = row["product"]
        case_id += 1
        cases.append({
            "case_id": f"single-{case_id:04d}",
            "case_type": "single_positive" if any(labels.values()) else "single_negative",
            "version_relation": tag,
            "project_input": {"name": f"eval-{case_id}", "technologies": [mk_asset(name, ver, row)]},
            "gold": {"labels": {f"{name}|{vid}": lab for vid, lab in labels.items()},
                     "expected_positive_ids": sorted(v for v, l in labels.items() if l)},
        })

    # ---------------- alias / noisy-name cases ----------------
    alias_cases = []
    for c in [c for c in cases if c["case_type"] == "single_positive"][:60]:
        a = c["project_input"]["technologies"][0]
        for al in aliases(a["name"])[:1]:
            case_id += 1
            alias_cases.append({
                "case_id": f"alias-{case_id:04d}", "case_type": "alias_positive",
                "version_relation": c["version_relation"],
                "project_input": {"name": f"eval-{case_id}",
                                  "technologies": [{**a, "name": al, "vendor": None}]},
                "gold": {"labels": {f"{al}|{k.split('|')[1]}": v for k, v in c["gold"]["labels"].items()},
                         "expected_positive_ids": c["gold"]["expected_positive_ids"],
                         "canonical_name": a["name"]},
            })
    cases += alias_cases[:30]

    # ---------------- unrelated (should return nothing) ----------------
    unrelated = [(n, v) for n, v in UNRELATED if n.lower() not in all_text]
    for n, v in unrelated:
        case_id += 1
        cases.append({"case_id": f"unrel-{case_id:04d}", "case_type": "unrelated",
                      "project_input": {"name": f"eval-{case_id}", "technologies": [{"name": n, "version": v, "type": "library"}]},
                      "gold": {"labels": {}, "expected_positive_ids": []}})

    # ---------------- mixed multi-asset projects ----------------
    pos_pool = [i for i in singles if any(i[3].values())]
    neg_pool = [i for i in singles if not any(i[3].values())]
    mixed = []
    for k in range(args.n_mixed):
        picks = rnd.sample(pos_pool, min(rnd.randint(1, 3), len(pos_pool))) + \
                rnd.sample(neg_pool, min(rnd.randint(1, 2), len(neg_pool)))
        seen, techs, labels, expected = set(), [], {}, []
        for pk, ver, tag, lab in picks:
            if pk in seen: continue
            seen.add(pk)
            row = by_product[pk][0]
            techs.append(mk_asset(row["product"], ver, row))
            for vid, l in lab.items():
                labels[f"{row['product']}|{vid}"] = l
                if l: expected.append(vid)
        for n, v in rnd.sample(unrelated, min(2, len(unrelated))):
            techs.append({"name": n, "version": v, "type": "library"})
        rnd.shuffle(techs)
        case_id += 1
        mixed.append({"case_id": f"mixed-{case_id:04d}", "case_type": "mixed_project",
                      "project_input": {"name": f"eval-{case_id}", "technologies": techs},
                      "gold": {"labels": labels, "expected_positive_ids": sorted(set(expected))}})
    cases += mixed

    with open(out / "assessment_eval.jsonl", "w") as f:
        for c in cases: f.write(json.dumps(c) + "\n")

    # ---------------- extraction cases ----------------
    ext = []
    for i, c in enumerate(mixed):
        techs = c["project_input"]["technologies"]
        gold_assets = [{"name": t["name"].lower(), "version": t["version"]} for t in techs]
        style = i % 3
        if style == 0:      # free text
            desc = "Our platform is built with " + ", ".join(f"{t['name']} {t['version']}" for t in techs[:-1]) + \
                   f" and {techs[-1]['name']} version {techs[-1]['version']}."
            inp = {"name": c["project_input"]["name"], "description": desc}
        elif style == 1:    # requirements-like dependency strings
            inp = {"name": c["project_input"]["name"], "dependencies": [f"{t['name']}=={t['version']}" for t in techs]}
        else:               # structured (control group - should be ~100%)
            inp = {"name": c["project_input"]["name"],
                   "technologies": [{"name": t["name"], "version": t["version"]} for t in techs]}
        ext.append({"case_id": f"ext-{i:03d}", "style": ["free_text", "dependencies", "structured"][style],
                    "project_input": inp, "gold_assets": gold_assets})
    with open(out / "extraction_eval.jsonl", "w") as f:
        for e in ext: f.write(json.dumps(e) + "\n")

    # ---------------- retrieval cases ----------------
    ret = []
    sample_ids = rnd.sample(rows, min(40, len(rows)))
    for r in sample_ids:
        ret.append({"qid": f"id-{r['vuln_id']}", "qtype": "id_exact", "query": r["cve"] or r["vuln_id"],
                    "relevant": sorted({x["vuln_id"] for x in rows if (r["cve"] and x["cve"] == r["cve"]) or x["vuln_id"] == r["vuln_id"]})})
    for pk, group in by_product.items():
        name = group[0]["product"]
        ret.append({"qid": f"prod-{pk}", "qtype": "product_all", "query": f"{name} vulnerabilities",
                    "relevant": sorted(r["vuln_id"] for r in group)})
    for c in [c for c in cases if c["case_type"] == "single_positive"][:40]:
        a = c["project_input"]["technologies"][0]
        ret.append({"qid": f"pv-{c['case_id']}", "qtype": "product_version", "query": f"{a['name']} {a['version']} vulnerability",
                    "relevant": c["gold"]["expected_positive_ids"]})
    desc_rows = [r for r in rows if len(r["description"]) > 120]
    for r in rnd.sample(desc_rows, min(args.n_retrieval_desc, len(desc_rows))):
        q = mask(r["description"], r["product"], r["vendor"])[:220]
        ret.append({"qid": f"desc-{r['vuln_id']}", "qtype": "description_semantic", "query": q, "relevant": [r["vuln_id"]]})
    with open(out / "retrieval_eval.jsonl", "w") as f:
        for q in ret: f.write(json.dumps(q) + "\n")

    # ---------------- index + stats ----------------
    json.dump({r["vuln_id"]: {k: r[k] for k in ("cve", "vendor", "product", "affected", "patched", "cvss", "epss", "kev")}
               for r in rows}, open(out / "corpus_index.json", "w"))
    stats = {"corpus_rows": len(rows),
             "rows_with_product_and_versions (usable for ground truth)": sum(len(g) for g in by_product.values()),
             "distinct_products": len(by_product),
             "assessment_cases": {t: sum(c["case_type"] == t for c in cases) for t in sorted({c["case_type"] for c in cases})},
             "extraction_cases": len(ext),
             "retrieval_queries": {t: sum(q["qtype"] == t for q in ret) for t in sorted({q["qtype"] for q in ret})}}
    json.dump(stats, open(out / "dataset_stats.json", "w"), indent=2)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()