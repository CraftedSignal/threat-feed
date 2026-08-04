---
title: Remote Code Execution in Flowise CSVAgent via pandas.read_pickle
slug: 2026-08-flowise-rce
description: A critical remote code execution vulnerability (CVE-2026-69256) in the Flowise CSVAgent node allows attackers to bypass security filters by deserializing malicious pickled payloads using pandas.
date: "2026-08-04T17:23:57Z"
lastmod: "2026-08-04T17:25:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - python
  - deserialization
  - web-security
  - ssrf
  - web-application
  - cloud
  - flowise
  - auth-bypass
  - exfiltration
  - cve-2026-69250
vendors:
  - Flowise
products:
  - flowise
  - flowise-components
  - Flowise (<= 3.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can supply a crafted pickled payload via the customReadCSVFunc parameter to achieve arbitrary command execution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.001
    technique_name: Abuse Elevation Control Mechanism
    evidence: The delete route accepts either chatflows:delete or agentflows:delete, and the subsequent logic does not validate the target resource type.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The POST /api/v1/prediction/:id endpoint — which is unauthenticated (whitelisted in WHITELIST_URLS) — accepts an overrideConfig object in the request body.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The application captures the HTTP response body from the remote target and reflects it directly to the user in the API response field tokenInfo, facilitating... the exfiltration of credentials.
    confidence_band: high
cves:
  - id: CVE-2026-69256
references:
  - https://github.com/advisories/GHSA-x6vm-w76m-8j7g
  - https://github.com/advisories/GHSA-p5w8-m249-4r4v
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69262
  - https://github.com/advisories/GHSA-6vh2-wg4h-4vwj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69258
  - https://github.com/advisories/GHSA-c6xh-wv4j-ppv5
  - https://github.com/advisories/GHSA-r745-8hwv-h473
rules:
  - title: Detect CVE-2026-69256 Exploitation - pandas.read_pickle in CSVAgent
    description: Detects exploitation attempts against the CSVAgent node by monitoring for the use of read_pickle in user-supplied parameters to the prediction API.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
  - title: Detect Unauthenticated Access to OAuth2 Refresh Endpoint
    description: Detects potentially malicious unauthenticated requests to the Flowise OAuth2 refresh endpoint which should be protected by authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-08-04T17:24:42Z"
    level: L2
    summary: 'merged source coverage: Flowise Authorization Bypass in DELETE API Endpoint'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-p5w8-m249-4r4v
  - at: "2026-08-04T17:24:50Z"
    level: L2
    summary: 'merged source coverage: Flowise Unauthenticated Property Injection in Prediction API'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-6vh2-wg4h-4vwj
  - at: "2026-08-04T17:24:58Z"
    level: L2
    summary: 'merged source coverage: Flowise SSRF Protection Bypass via IPv4-Mapped IPv6 Addresses'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-c6xh-wv4j-ppv5
  - at: "2026-08-04T17:25:15Z"
    level: L2
    summary: 'added detection rule: Detect Unauthenticated Access to OAuth2 Refresh Endpoint'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-r745-8hwv-h473
---

Flowise versions 3.1.2 and below contain a remote code execution (RCE) vulnerability in the CSVAgent node (CVE-2026-69256). The component was designed to allow users to process CSV data via the pandas library while restricting potentially dangerous Python constructs through a denylist-based validation mechanism. However, the existing filter fails to account for the pandas `read_pickle()` function, which can be leveraged to deserialize arbitrary data. By crafting a malicious pickle payload that triggers OS-level execution (e.g., via `os.system`) and providing it through the `customReadCSVFunc` parameter, an attacker can bypass all configured security checks. Since the environment lacks standard I/O modules due to the filter, attackers can implement custom file-like classes to bridge the object into the `read_pickle()` function, successfully achieving full system command execution.

## Attack Chain

1. Attacker creates a malicious pickle object containing a payload designed to execute arbitrary shell commands (e.g., `os.system`).
2. The payload is encoded in base64 to ensure successful transport within the Flowise input parameters.
3. The attacker defines a custom Python class (e.g., `MiniBytesIO`) within the `customReadCSVFunc` parameter to simulate a file-like object, bypassing constraints on importing standard library I/O modules.
4. The attacker injects the encoded pickle string into the `read_pickle()` call within the `customReadCSVFunc` parameter in the Flowise UI.
5. The Flowise CSVAgent node accepts the user-supplied input, as it does not explicitly filter for `read_pickle` or the required pickle-loading logic.
6. The `pyodide` execution environment processes the provided string and invokes `pandas.read_pickle()`.
7. The pickle deserialization occurs, triggering the `__reduce__` method of the malicious object and executing the embedded shell commands.
8. The attacker triggers the execution by sending a POST request to the prediction endpoint (`/api/v1/prediction/<UUID>`), resulting in unauthorized command execution on the host.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary commands with the privileges of the Flowise application process. This can lead to full system compromise, exfiltration of sensitive configuration or chat data, and potential lateral movement within the environment.

## Recommendation

- Upgrade Flowise and the flowise-components package to version 3.1.3 or higher to apply the vendor-provided patch.
- Apply the following webserver detection rule to identify and block incoming requests targeting the prediction endpoint with suspicious `customReadCSVFunc` payloads.
- Implement egress filtering on the Flowise host to restrict unexpected network connections originating from the application process, mitigating the impact of successful RCE (e.g., reverse shells).
