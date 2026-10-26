# CyberRAG Retrieval Evaluation Report

- Status: **completed**
- Result rows: 48
- Unique queries: 12

> This report is generated from the current run. Failed/skipped strategies are not assigned scores.

## Strategy: `hybrid`

- Errors: 0
- Empty-result rate: 0.0000
- Average latency: 2500.3405 ms
- Retrieval modes: `{"HYBRID": 12}`

| K | Hit Rate | Recall | Precision | MRR | nDCG | Labelled queries | Known no-relevant |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 0.8750 | 1.0000 | 0.1750 | 0.5714 | 0.6792 | 7 | 1 |
| 10 | 0.8750 | 1.0000 | 0.0875 | 0.5714 | 0.6792 | 7 | 1 |

### Per-category ranking metrics

| Category | K | Hit Rate | Recall | Precision | MRR | nDCG |
|---|---:|---:|---:|---:|---:|---:|
| advisory_identifier | 5 | N/A | N/A | N/A | N/A | N/A |
| advisory_identifier | 10 | N/A | N/A | N/A | N/A | N/A |
| affected_patched_versions | 5 | 1.0000 | 1.0000 | 0.2000 | 0.5000 | 0.6309 |
| affected_patched_versions | 10 | 1.0000 | 1.0000 | 0.1000 | 0.5000 | 0.6309 |
| ambiguous_product | 5 | N/A | N/A | N/A | N/A | N/A |
| ambiguous_product | 10 | N/A | N/A | N/A | N/A | N/A |
| epss_cvss | 5 | 1.0000 | 1.0000 | 0.2000 | 0.2500 | 0.4307 |
| epss_cvss | 10 | 1.0000 | 1.0000 | 0.1000 | 0.2500 | 0.4307 |
| exact_advisory_id | 5 | N/A | N/A | N/A | N/A | N/A |
| exact_advisory_id | 10 | N/A | N/A | N/A | N/A | N/A |
| exact_cve | 5 | 1.0000 | 1.0000 | 0.2000 | 1.0000 | 1.0000 |
| exact_cve | 10 | 1.0000 | 1.0000 | 0.1000 | 1.0000 | 1.0000 |
| kev_exploit | 5 | 1.0000 | 1.0000 | 0.2000 | 0.2500 | 0.4307 |
| kev_exploit | 10 | 1.0000 | 1.0000 | 0.1000 | 0.2500 | 0.4307 |
| natural_language | 5 | 1.0000 | 1.0000 | 0.2000 | 0.5000 | 0.6309 |
| natural_language | 10 | 1.0000 | 1.0000 | 0.1000 | 0.5000 | 0.6309 |
| no_relevant_results | 5 | 0.0000 | N/A | 0.0000 | N/A | N/A |
| no_relevant_results | 10 | 0.0000 | N/A | 0.0000 | N/A | N/A |
| product_version | 5 | 1.0000 | 1.0000 | 0.2000 | 0.5000 | 0.6309 |
| product_version | 10 | 1.0000 | 1.0000 | 0.1000 | 0.5000 | 0.6309 |
| vendor_product | 5 | 1.0000 | 1.0000 | 0.2000 | 1.0000 | 1.0000 |
| vendor_product | 10 | 1.0000 | 1.0000 | 0.1000 | 1.0000 | 1.0000 |
| vulnerability_type | 5 | N/A | N/A | N/A | N/A | N/A |
| vulnerability_type | 10 | N/A | N/A | N/A | N/A | N/A |

### Reliability

- Exact-identifier success: 0.5000 (1/2)
- PostgreSQL identifier resolution: 1.0000 (12/12 checked)

## Strategy: `lexical`

- Errors: 0
- Empty-result rate: 0.0833
- Average latency: 27.4242 ms
- Retrieval modes: `{"LEXICAL_ONLY": 12}`

| K | Hit Rate | Recall | Precision | MRR | nDCG | Labelled queries | Known no-relevant |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 0.1250 | 0.1429 | 0.0250 | 0.1429 | 0.1429 | 7 | 1 |
| 10 | 0.1250 | 0.1429 | 0.0125 | 0.1429 | 0.1429 | 7 | 1 |

### Per-category ranking metrics

| Category | K | Hit Rate | Recall | Precision | MRR | nDCG |
|---|---:|---:|---:|---:|---:|---:|
| advisory_identifier | 5 | N/A | N/A | N/A | N/A | N/A |
| advisory_identifier | 10 | N/A | N/A | N/A | N/A | N/A |
| affected_patched_versions | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| affected_patched_versions | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| ambiguous_product | 5 | N/A | N/A | N/A | N/A | N/A |
| ambiguous_product | 10 | N/A | N/A | N/A | N/A | N/A |
| epss_cvss | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| epss_cvss | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| exact_advisory_id | 5 | N/A | N/A | N/A | N/A | N/A |
| exact_advisory_id | 10 | N/A | N/A | N/A | N/A | N/A |
| exact_cve | 5 | 1.0000 | 1.0000 | 0.2000 | 1.0000 | 1.0000 |
| exact_cve | 10 | 1.0000 | 1.0000 | 0.1000 | 1.0000 | 1.0000 |
| kev_exploit | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| kev_exploit | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| natural_language | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| natural_language | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| no_relevant_results | 5 | 0.0000 | N/A | 0.0000 | N/A | N/A |
| no_relevant_results | 10 | 0.0000 | N/A | 0.0000 | N/A | N/A |
| product_version | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| product_version | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| vendor_product | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| vendor_product | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| vulnerability_type | 5 | N/A | N/A | N/A | N/A | N/A |
| vulnerability_type | 10 | N/A | N/A | N/A | N/A | N/A |

### Reliability

- Exact-identifier success: 0.5000 (1/2)
- PostgreSQL identifier resolution: 0.9167 (11/12 checked)

## Strategy: `postgresql_fallback`

- Errors: 0
- Empty-result rate: 0.0833
- Average latency: 26.2353 ms
- Retrieval modes: `{"POSTGRESQL_FALLBACK_FORCED": 12}`

| K | Hit Rate | Recall | Precision | MRR | nDCG | Labelled queries | Known no-relevant |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 0.1250 | 0.1429 | 0.0250 | 0.1429 | 0.1429 | 7 | 1 |
| 10 | 0.1250 | 0.1429 | 0.0125 | 0.1429 | 0.1429 | 7 | 1 |

### Per-category ranking metrics

| Category | K | Hit Rate | Recall | Precision | MRR | nDCG |
|---|---:|---:|---:|---:|---:|---:|
| advisory_identifier | 5 | N/A | N/A | N/A | N/A | N/A |
| advisory_identifier | 10 | N/A | N/A | N/A | N/A | N/A |
| affected_patched_versions | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| affected_patched_versions | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| ambiguous_product | 5 | N/A | N/A | N/A | N/A | N/A |
| ambiguous_product | 10 | N/A | N/A | N/A | N/A | N/A |
| epss_cvss | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| epss_cvss | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| exact_advisory_id | 5 | N/A | N/A | N/A | N/A | N/A |
| exact_advisory_id | 10 | N/A | N/A | N/A | N/A | N/A |
| exact_cve | 5 | 1.0000 | 1.0000 | 0.2000 | 1.0000 | 1.0000 |
| exact_cve | 10 | 1.0000 | 1.0000 | 0.1000 | 1.0000 | 1.0000 |
| kev_exploit | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| kev_exploit | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| natural_language | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| natural_language | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| no_relevant_results | 5 | 0.0000 | N/A | 0.0000 | N/A | N/A |
| no_relevant_results | 10 | 0.0000 | N/A | 0.0000 | N/A | N/A |
| product_version | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| product_version | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| vendor_product | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| vendor_product | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| vulnerability_type | 5 | N/A | N/A | N/A | N/A | N/A |
| vulnerability_type | 10 | N/A | N/A | N/A | N/A | N/A |

### Reliability

- Exact-identifier success: 0.5000 (1/2)
- PostgreSQL identifier resolution: 0.9167 (11/12 checked)

## Strategy: `semantic`

- Errors: 0
- Empty-result rate: 0.0000
- Average latency: 2399.4172 ms
- Retrieval modes: `{"SEMANTIC_ONLY": 12}`

| K | Hit Rate | Recall | Precision | MRR | nDCG | Labelled queries | Known no-relevant |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 0.7500 | 0.8571 | 0.1500 | 0.7143 | 0.7517 | 7 | 1 |
| 10 | 0.7500 | 0.8571 | 0.0750 | 0.7143 | 0.7517 | 7 | 1 |

### Per-category ranking metrics

| Category | K | Hit Rate | Recall | Precision | MRR | nDCG |
|---|---:|---:|---:|---:|---:|---:|
| advisory_identifier | 5 | N/A | N/A | N/A | N/A | N/A |
| advisory_identifier | 10 | N/A | N/A | N/A | N/A | N/A |
| affected_patched_versions | 5 | 1.0000 | 1.0000 | 0.2000 | 1.0000 | 1.0000 |
| affected_patched_versions | 10 | 1.0000 | 1.0000 | 0.1000 | 1.0000 | 1.0000 |
| ambiguous_product | 5 | N/A | N/A | N/A | N/A | N/A |
| ambiguous_product | 10 | N/A | N/A | N/A | N/A | N/A |
| epss_cvss | 5 | 1.0000 | 1.0000 | 0.2000 | 0.5000 | 0.6309 |
| epss_cvss | 10 | 1.0000 | 1.0000 | 0.1000 | 0.5000 | 0.6309 |
| exact_advisory_id | 5 | N/A | N/A | N/A | N/A | N/A |
| exact_advisory_id | 10 | N/A | N/A | N/A | N/A | N/A |
| exact_cve | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| exact_cve | 10 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| kev_exploit | 5 | 1.0000 | 1.0000 | 0.2000 | 0.5000 | 0.6309 |
| kev_exploit | 10 | 1.0000 | 1.0000 | 0.1000 | 0.5000 | 0.6309 |
| natural_language | 5 | 1.0000 | 1.0000 | 0.2000 | 1.0000 | 1.0000 |
| natural_language | 10 | 1.0000 | 1.0000 | 0.1000 | 1.0000 | 1.0000 |
| no_relevant_results | 5 | 0.0000 | N/A | 0.0000 | N/A | N/A |
| no_relevant_results | 10 | 0.0000 | N/A | 0.0000 | N/A | N/A |
| product_version | 5 | 1.0000 | 1.0000 | 0.2000 | 1.0000 | 1.0000 |
| product_version | 10 | 1.0000 | 1.0000 | 0.1000 | 1.0000 | 1.0000 |
| vendor_product | 5 | 1.0000 | 1.0000 | 0.2000 | 1.0000 | 1.0000 |
| vendor_product | 10 | 1.0000 | 1.0000 | 0.1000 | 1.0000 | 1.0000 |
| vulnerability_type | 5 | N/A | N/A | N/A | N/A | N/A |
| vulnerability_type | 10 | N/A | N/A | N/A | N/A | N/A |

### Reliability

- Exact-identifier success: 0.0000 (0/2)
- PostgreSQL identifier resolution: 1.0000 (12/12 checked)

## Metric conventions

- Retrieved IDs are de-duplicated by keeping their first rank.
- Precision@K divides by K even when fewer than K records are returned.
- Queries with a missing relevance label are invalid and recorded as errors.
- Queries with a verified empty relevant set are treated as known negatives; Recall, MRR and nDCG are undefined and excluded from those metric means.
- nDCG uses binary gain for list/set labels or graded gains for `{id: gain}` labels.
