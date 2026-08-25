---
title: Unauthenticated Remote Code Execution in DB-GPT via Path Traversal
slug: 2026-08-dbgpt-path-traversal
description: An unauthenticated path traversal vulnerability in DB-GPT allows remote attackers to write arbitrary files and achieve remote code execution by uploading malicious Python modules to the application server.
date: "2026-08-25T22:49:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - path-traversal
  - webserver
vendors:
  - Eosphoros-AI
products:
  - DB-GPT
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote attacker holding no account can therefore write attacker-controlled bytes to any path the server process can write.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: place a new Python module inside the application package or replace one the application already imports, and obtain code execution in the server process
    confidence_band: high
cves:
  - id: CVE-2026-80104
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80104
rules:
  - title: Detect CVE-2026-80104 Exploitation - Path Traversal in Skill Upload
    description: Detects exploitation of CVE-2026-80104 via path traversal patterns in the multipart filename during skill uploads to the DB-GPT API.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch DB-GPT instance
      owner: IT Operations
      due: 24h
      evidence: Source confirms critical RCE vulnerability
    - action: Monitor/block traffic to skill_upload endpoint
      owner: SOC
      due: 24h
      evidence: Vulnerability allows unauthenticated access
  mitigation_plan:
    - priority: immediate
      action: Network segmentation
      owner: IT Operations
      addresses: CVE-2026-80104
      evidence: NVD severity score 9.8
---

DB-GPT is susceptible to a critical path traversal vulnerability (CVE-2026-80104) arising from improper validation of multipart filenames during skill uploads. The vulnerable function, `skill_upload` located in `packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py`, constructs file paths by concatenating a base directory with the user-provided filename without performing canonicalization or restriction to the upload directory. 

Crucially, an authentication bypass in `dbgpt_serve/utils/auth.py` allows unauthenticated users to access this API endpoint. By submitting a crafted filename containing parent directory references (e.g., `../../../`) or absolute paths, an attacker can write arbitrary files to the server's filesystem. An attacker can leverage this primitive to drop a malicious Python module into an application directory. Given the application's structure, the server process will execute the attacker-controlled code upon the subsequent import of the corrupted module. This vulnerability allows for full system compromise from an unauthenticated remote position.

## Attack Chain

1. Attacker identifies the target DB-GPT instance reachable via the network.
2. Attacker crafts a multipart HTTP request targeting the `skill_upload` API endpoint.
3. Attacker sets the multipart `filename` attribute to a path-traversal string, such as `../../../path/to/malicious_module.py`.
4. Attacker includes the payload (Python code) in the request body to be written to the target location.
5. The server process, lacking filename validation, writes the file to the malicious destination on the filesystem.
6. The application performs a subsequent operation or import that loads the newly created `.py` file.
7. The Python interpreter executes the attacker-controlled script within the context of the server process.
8. Attacker gains persistent remote code execution and potential full system compromise.

## Impact

Successful exploitation of CVE-2026-80104 leads to unauthenticated Remote Code Execution (RCE) on the DB-GPT server. This allows an attacker to execute arbitrary system commands, steal sensitive data, or install persistent backdoors. Given that DB-GPT often handles AI/ML configurations and model artifacts, the impact includes potential exfiltration of proprietary datasets and credentials.

## Recommendation

* Immediately restrict network access to the DB-GPT API endpoint to trusted internal networks only.
* Update DB-GPT to the patched version that implements filename canonicalization and validates that the destination path resides within the intended upload directory.
* Audit the `packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py` module for improper path concatenation practices.
* Deploy webserver logs monitoring to detect POST requests to the `skill_upload` endpoint that contain directory traversal patterns (e.g., `..%2f` or `../`).
* Implement stricter authentication checks in `dbgpt_serve/utils/auth.py` to ensure only verified users can access administrative API endpoints.
