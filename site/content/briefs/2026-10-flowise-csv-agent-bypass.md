---
title: Flowise CSV and Airtable Agent Python Validator Bypass
slug: 2026-10-flowise-csv-agent-bypass
description: Flowise versions <= 3.1.2 are vulnerable to data exfiltration and SSRF via a flawed regex-based Python validator that fails to restrict pre-imported pandas and numpy methods.
date: "2026-10-07T16:55:52Z"
lastmod: "2026-10-07T16:56:17Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - prompt-injection
  - rce
  - ssrf
  - exfiltration
  - vulnerability
  - sandbox-escape
vendors:
  - Flowise
products:
  - Flowise (<= 3.1.2)
  - flowise-components (<= 3.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The validator bypass is reachable via the unauthenticated prediction API.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: The vulnerability allows arbitrary execution of Python code in the Pyodide environment.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Data is exfiltrated by leveraging pandas functions that make outbound HTTP requests.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An authenticated user with access to the /api/v1/node-custom-function endpoint can escape the sandbox by supplying attacker-controlled executablePath and args parameters.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This allows execution of arbitrary OS commands as the Flowise process user.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w7x8-q2gp-5cgg
  - https://github.com/advisories/GHSA-9gvv-qjj3-2p6g
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73483
iocs:
  - type: url
    value: http://169.254.169.254/latest/meta-data/
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious Flowise Prediction API Payloads
    description: Detects potential prompt injection attempts against the Flowise prediction API containing Python code patterns used to bypass the validator.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Exploitation of CVE-2026-73483 in Flowise
    description: Detects potential exploitation attempts of the node-custom-function endpoint by monitoring for requests containing puppeteer configuration parameters like executablePath.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit all Flowise deployments for exposure to the prediction API.
      owner: SOC
      due: 24h
      evidence: Unauthenticated prediction endpoint is a core requirement for the attack.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the /api/v1/prediction/ endpoint to authenticated users only.
      owner: IT Operations
      addresses: All Flowise nodes
      evidence: GHSA-w7x8-q2gp-5cgg
updates:
  - at: "2026-10-07T16:56:17Z"
    level: L2
    summary: 'added detection rule: Detect Exploitation of CVE-2026-73483 in Flowise'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-9gvv-qjj3-2p6g
---

Flowise versions 3.1.2 and earlier contain a critical security vulnerability in the CSV and Airtable agent nodes. These nodes utilize a structurally insufficient regex-based blocklist (`validatePythonCodeForDataFrame()`) to sanitize LLM-generated Python code before execution in a Pyodide (WebAssembly) environment. The blocklist approach fails because the executor pre-imports pandas and numpy, exposing broad API surfaces that accept network-capable functions (e.g., `pd.read_json`, `pd.read_csv`, `pd.read_html`) which are not filtered.

Attackers can leverage prompt injection via the unauthenticated prediction API to force the LLM to generate bypass code. This code executes in the Flowise backend, allowing attackers to exfiltrate dataset contents, conduct SSRF against internal services or cloud metadata endpoints, and attempt to load native libraries using `np.ctypeslib`. This finding persists despite previous patches in version 3.1.0 that addressed different import aliasing techniques, highlighting the fundamental insecurity of using regex blocklists for code execution validation.

## Attack Chain

1. Attacker identifies a Flowise instance exposing a CSV Agent or Airtable Agent chatflow endpoint.
2. Attacker sends a POST request to the unauthenticated `/api/v1/prediction/:id` endpoint containing a malicious prompt injection payload.
3. The LLM processes the prompt and is steered to generate Python code leveraging unrestricted pandas functions like `pd.read_json()`.
4. The Flowise `validatePythonCodeForDataFrame()` function scans the generated code against the 38-pattern regex blocklist.
5. The validator fails to trigger because the functions used (e.g., `pd.read_json`) are not in the blocklist and no forbidden keywords like `import` are utilized.
6. The Pyodide runtime executes the generated code, prepended with pre-imported `pandas` and `numpy` libraries.
7. The `pd.read_json()` function makes an outbound HTTP request to an attacker-controlled server containing the serialized CSV dataset or sensitive cloud metadata obtained via SSRF.
8. The attacker receives the sensitive data via their listener, completing the exfiltration.

## Impact

Successful exploitation allows unauthenticated attackers to steal sensitive data loaded into CSV or Airtable agents, access cloud metadata services (e.g., `169.254.169.254`), and perform internal network reconnaissance. Because the vulnerability is reachable via the default prediction API without authentication, it poses a high risk to any deployment where these agents are active.

## Recommendation

1. Implement an AST-based allowlist for Python code execution instead of relying on regex blocklists.
2. Block all pandas and numpy functions capable of network I/O, such as `pd.read_json`, `pd.read_csv`, `pd.read_html`, and `pd.read_fwf`.
3. Restrict access to the `/api/v1/prediction/` endpoint by enforcing authentication.
4. Monitor web server logs for high-frequency or suspicious POST requests to the prediction endpoint containing Python-like syntax in the `question` field.
