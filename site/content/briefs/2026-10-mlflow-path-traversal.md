---
title: Path Traversal in MLflow FileStore via CVE-2026-53995
slug: 2026-10-mlflow-path-traversal
description: MLflow FileStore is vulnerable to a path traversal attack allowing arbitrary file creation through malicious trace_id parameters in the start_trace_v3 API endpoint.
date: "2026-10-18T01:12:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - path-traversal
  - cve-2026-53995
  - mlflow
  - vulnerability
vendors:
  - MLflow
products:
  - MLflow (<= 3.17.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The PoC exercises the route via Python scripts on Windows environments to demonstrate arbitrary file write primitives.
    confidence_band: med
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review and restrict access to the MLflow /api/3.0/mlflow/traces endpoint
      owner: SOC
      due: 24h
      evidence: Source remediation guidance identifies this as a necessary interim measure.
  mitigation_plan:
    - priority: immediate
      action: Upgrade MLflow to a patched version once released or implement the validation logic in fix.md
      owner: IT Operations
      addresses: CVE-2026-53995
      evidence: Remediation section requires path validation at the FileStore boundary.
---

MLflow versions through 3.17.1 contain a path traversal vulnerability in the FileStore component, identified as CVE-2026-53995. The flaw exists within the handling of the `trace_id` parameter when processing requests to the `/api/3.0/mlflow/traces` endpoint. By submitting a `trace_id` containing directory traversal sequences, such as `../../../`, an attacker can bypass the intended directory structure of the `mlruns/` storage path. 

When the `FileStore.start_trace()` function processes the `trace_info` proto containing a malicious ID, it incorrectly joins the path, enabling the application to write metadata, trace information, and tag files outside of the designated experiment trace directory. This vulnerability provides an arbitrary file write primitive, which could be leveraged to overwrite configuration files or place malicious files on the host filesystem. The issue was disclosed by Sai Teja Erukude and confirmed to affect the standard FileStore backend implementation in MLflow.

## Attack Chain

1. Attacker identifies a target running an vulnerable MLflow instance (<= 3.17.1).
2. Attacker crafts a malicious `StartTraceV3` request targeting the `/api/3.0/mlflow/traces` endpoint.
3. The `trace_id` field within the JSON request body is populated with path traversal sequences like `../../../[custom-dir]`.
4. The MLflow server receives the request and parses the `trace_info` structure.
5. The `FileStore` component incorrectly joins the malicious `trace_id` with the base storage path.
6. The application resolves the path to a location outside of the intended `mlruns/` directory hierarchy.
7. The application writes trace metadata, tags, and state files to the attacker-controlled path on the underlying filesystem.
8. Attacker successfully creates or overwrites files on the host system, potentially leading to further compromise.

## Impact

Successful exploitation allows for arbitrary file creation on the filesystem where MLflow is deployed. This can result in unauthorized data modification, potential service disruption, or the placement of malicious artifacts. While the CVSS score is 6.2, the impact depends on the service account privileges running the MLflow server, which could grant an attacker write access to sensitive system directories or application configurations.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:

- Implement strict input validation on the `trace_id` field in the MLflow API to reject path separators, traversal segments (`../`), absolute paths, and drive letters.
- Deploy an allow-list for `trace_id` components to ensure all trace storage operations remain within the designated experiment trace directory.
- Monitor webserver access logs for POST requests to `/api/3.0/mlflow/traces` containing path traversal sequences or unexpected characters in the request body.
- Restrict access to the trace-creation endpoint until a patched version of MLflow is deployed to your environment.
- If feasible, migrate trace tracking from the FileStore backend to a secure SQL backend, ensuring appropriate compatibility checks are performed.
- Review the provided `fix.md` and reproduction `run_poc.py` to understand the vulnerable path resolution logic and validate internal environments against the documented regression patterns.
