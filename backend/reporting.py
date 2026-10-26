{
  "schema_version": 1,
  "description": "Retrieval-only golden set. Manually labelled hypotheses are NOT claimed verified until run with --verify-golden against the configured PostgreSQL database. Replace or confirm each label before treating metrics as a benchmark.",
  "cases": [
    {
      "id": "retrieval_001",
      "query": "CVE-2021-44228",
      "expected_relevant_ids": ["CVE-2021-44228"],
      "category": "exact_cve",
      "label_source": "manual_candidate_unverified",
      "notes": "Expected label is a known Log4Shell identifier; database presence must be verified locally."
    },
    {
      "id": "retrieval_002",
      "query": "GHSA-xxxx-xxxx-xxxx",
      "expected_relevant_ids": null,
      "category": "exact_advisory_id",
      "label_source": "needs_manual_label",
      "notes": "Intentionally unlabelled placeholder: replace with an actual GHSA identifier present in PostgreSQL and label it before evaluation. This case is skipped with an explicit dataset validation error, never scored."
    },
    {
      "id": "retrieval_003",
      "query": "Apache Log4j remote code execution",
      "expected_relevant_ids": ["CVE-2021-44228"],
      "category": "vendor_product",
      "label_source": "manual_candidate_unverified",
      "notes": "Candidate label for Log4Shell; verify against actual indexed record and add other relevant CVEs if that is the intended judgment."
    },
    {
      "id": "retrieval_004",
      "query": "Log4j 2.14.1 remote code execution",
      "expected_relevant_ids": ["CVE-2021-44228"],
      "category": "product_version",
      "label_source": "manual_candidate_unverified",
      "notes": "Candidate affected-version query label; confirm affected-version details against the database's record."
    },
    {
      "id": "retrieval_005",
      "query": "remote code execution in a Java logging library through JNDI lookup",
      "expected_relevant_ids": ["CVE-2021-44228"],
      "category": "natural_language",
      "label_source": "manual_candidate_unverified",
      "notes": "Candidate natural-language relevance label; manual review should consider whether other records are equally relevant."
    },
    {
      "id": "retrieval_006",
      "query": "remote code execution vulnerabilities",
      "expected_relevant_ids": null,
      "category": "vulnerability_type",
      "label_source": "needs_manual_label",
      "notes": "Many records may be relevant. Define a judged candidate pool and manually label the relevant IDs before metric use."
    },
    {
      "id": "retrieval_007",
      "query": "Log4j affected versions and patched version 2.17.0",
      "expected_relevant_ids": ["CVE-2021-44228"],
      "category": "affected_patched_versions",
      "label_source": "manual_candidate_unverified",
      "notes": "Candidate label for a version-range evidence query; verify record fields locally."
    },
    {
      "id": "retrieval_008",
      "query": "CISA KEV Log4Shell exploited vulnerability",
      "expected_relevant_ids": ["CVE-2021-44228"],
      "category": "kev_exploit",
      "label_source": "manual_candidate_unverified",
      "notes": "The current retriever accepts KEV/exploit filters, but query terms alone do not impose those filters; verify the record and search behavior."
    },
    {
      "id": "retrieval_009",
      "query": "EPSS probability and CVSS severity for Apache Log4j",
      "expected_relevant_ids": ["CVE-2021-44228"],
      "category": "epss_cvss",
      "label_source": "manual_candidate_unverified",
      "notes": "Candidate record-retrieval label; retrieval relevance does not evaluate correctness of the EPSS/CVSS values."
    },
    {
      "id": "retrieval_010",
      "query": "Spring framework vulnerability",
      "expected_relevant_ids": null,
      "category": "ambiguous_product",
      "label_source": "needs_manual_label",
      "notes": "Ambiguous product/vendor phrase; manually judge a candidate pool, potentially with multiple relevant IDs."
    },
    {
      "id": "retrieval_011",
      "query": "vulnerability affecting a fictional product named blue-koala-enterprise-999",
      "expected_relevant_ids": [],
      "category": "no_relevant_results",
      "label_source": "manual_negative_unverified",
      "notes": "Intended known-negative query; confirm no relevant matching records exist before counting this as a true negative."
    },
    {
      "id": "retrieval_012",
      "query": "GHSA advisory for an installed package",
      "expected_relevant_ids": null,
      "category": "advisory_identifier",
      "label_source": "needs_manual_label",
      "notes": "Needs a concrete GHSA or other supported identifier and verified labels before scoring."
    }
  ]
}
