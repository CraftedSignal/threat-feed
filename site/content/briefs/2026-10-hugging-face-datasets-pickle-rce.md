---
brief_id: brief-2026-10-23-hugging-face-datasets-pickle-rce
event_id: brief-2026-10-23-hugging-face-datasets-pickle-rce
revision: 1
activity_at: "2026-10-23T03:20:38Z"
title: 'Hugging Face datasets: Arbitrary code execution via pickle deserialization (CVE-2026-57845)'
slug: 2026-10-hugging-face-datasets-pickle-rce
description: The Hugging Face 'datasets' library is vulnerable to arbitrary code execution (CVE-2026-57845) due to insecure deserialization of untrusted data via the pandas builder.
date: "2026-10-23T03:20:38Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass_with_fixes
cpes:
  - cpe:2.3:a:huggingface:datasets:*:*:*:*:*:*:*:*
vendors:
  - Hugging Face
products:
  - datasets (<= 5.1.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Arbitrary code execution in Hugging Face datasets via pandas pickle deserialization.
    confidence_band: high
cves:
  - id: CVE-2026-57845
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=F4E4EAEC-8A52-5213-893F-11BF7AC67BB6
  - https://vulners.com/cve/CVE-2026-57845
  - https://github.com/huggingface/datasets
  - https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html
  - https://sploitus.com/exploit?id=F4E4EAEC-8A52-5213-893F-11BF7AC67BB6&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all applications using huggingface/datasets and identify reliance on pickle-based ingestion.
      owner: SOC
      due: 24h
      evidence: 'Source states: ''The availability of a working exploit significantly elevates the risk for unpatched systems.'''
  mitigation_plan:
    - priority: immediate
      action: Disable pickle-based dataset loading; switch to Parquet or JSON formats.
      owner: IT Operations
      addresses: CVE-2026-57845
      evidence: 'Source recommends: ''Prefer Parquet, Arrow, CSV, or JSON for file exchange''.'
---

A vulnerability (CVE-2026-57845) exists in the Hugging Face `datasets` library, specifically within the `dataset_module_factory` pandas-based builder. The library uses `pandas.read_pickle()` to process data files without proper validation. An attacker can supply a malicious pickle file that executes arbitrary code during the deserialization process when `load_dataset()` is invoked. The PoC demonstrates successful code execution by triggering a local file write upon loading a malicious pickle object. There is currently no upstream fix, PR, or confirmed patched release.

## Attack Chain
1. Attacker prepares a malicious pickle object using the `__reduce__()` method to embed a payload.
2. Attacker hosts or supplies the malicious file as an input to the `load_dataset()` function.
3. Victim application invokes `datasets.load_dataset()` pointing to the malicious file.
4. The `dataset_module_factory` identifies the file and routes it to the `pandas` packaged builder.
5. The builder invokes `pandas.read_pickle()` on the untrusted input.
6. The `pickle` module deserializes the object, triggering the attacker-supplied callable.
7. Arbitrary code executes within the context of the application process.

## Impact
Successful exploitation results in arbitrary code execution on the system running the `datasets` library. The PoC confirms that code execution occurs before the library attempts to convert the data into an Arrow table, rendering post-deserialization validation ineffective.

## Recommendation
- Identify all instances of the Hugging Face `datasets` library in production and development environments using automated inventory tools.
- Immediately stop using pickle-formatted datasets from untrusted or external sources.
- Migrate all data exchange to secure formats such as Parquet, Arrow, CSV, or JSON.
- If existing data must be moved, use `Dataset.from_pandas()` with a trusted, already-loaded DataFrame rather than loading from disk via the `pandas` builder.
- Implement strict input validation or access controls to prevent the loading of pickle files from arbitrary or internet-accessible locations.
- Monitor logs for the execution of Python processes that import the `datasets` module and perform file operations in untrusted directories.
