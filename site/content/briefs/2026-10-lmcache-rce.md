---
title: Unauthenticated Remote Code Execution in LMCache
slug: 2026-10-lmcache-rce
description: LMCache versions up to 0.5.5 are vulnerable to unauthenticated remote code execution via the /run_script endpoint, allowing attackers to inject and execute arbitrary OS commands.
date: "2026-10-07T17:03:43Z"
lastmod: "2026-10-07T17:04:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:lmcache:lmcache:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - web-application
  - ssrf
  - web-vulnerability
  - proxy
vendors:
  - LMCache
products:
  - LMCache (<= 0.5.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: LMCache through 0.5.5 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute Python code by posting scripts to the /run_script endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: Attackers can recover real builtins through the injected FastAPI app object... to import os and run operating system commands as the LMCache process.
    confidence_band: high
cves:
  - id: CVE-2026-107204
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107204
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107207
rules:
  - title: Detects CVE-2026-107204 Exploitation - Unauthorized POST to /run_script
    description: Detects unauthorized attempts to access the /run_script endpoint which is associated with RCE exploitation in LMCache.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.006
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-107207 Exploitation - POST Request to /api/proxies
    description: Detects potential SSRF exploitation attempts where an unauthenticated actor attempts to register arbitrary hosts via the /api/proxies endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade LMCache to version 0.5.6 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-107204 indicates versions through 0.5.5 are vulnerable.
  hunt_leads:
    - lead: Search web logs for POST requests to /run_script from unauthorized IP ranges.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies /run_script as the exploitation vector.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the management endpoint /run_script via firewall or WAF.
      owner: IT Operations
      addresses: CVE-2026-107204
      evidence: Source notes the vulnerability is unauthenticated.
updates:
  - at: "2026-10-07T17:04:22Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-107207 Exploitation - POST Request to /api/proxies'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-107207
---

LMCache versions up to 0.5.5 contain a critical unauthenticated remote code execution (RCE) vulnerability. An attacker can exploit this by sending a crafted HTTP POST request to the /run_script endpoint. The application fails to properly secure the environment, allowing the attacker to interact with the FastAPI app object. By leveraging this object, an attacker can bypass Python's guarded import restrictions to retrieve real built-in functions, load the 'os' module, and subsequently execute arbitrary operating system commands with the privileges of the LMCache process. This vulnerability poses a severe risk, as it allows for full compromise of the underlying host system without requiring prior authentication. Organizations utilizing LMCache should prioritize patching to version 0.5.6 or higher or restrict network access to the management interface.

## Attack Chain

1. Attacker performs network reconnaissance to identify exposed LMCache instances.
2. Attacker sends a malicious HTTP POST request to the target's /run_script endpoint.
3. The LMCache application accepts the input and processes the provided script.
4. Attacker utilizes the FastAPI app object to access and recover restricted Python built-in functions.
5. Attacker bypasses guarded __import__ mechanisms to import the 'os' library.
6. Attacker invokes system functions within the Python script to execute arbitrary OS commands.
7. OS commands run with the privileges of the LMCache service process.
8. Attacker gains persistence or exfiltrates data from the compromised host.

## Impact

Successful exploitation of CVE-2026-107204 results in full remote code execution on the server running LMCache. An attacker gains the ability to execute arbitrary commands, potentially leading to complete system takeover, data exfiltration, or deployment of further payloads. Given the critical 9.8 CVSS score, this vulnerability is highly attractive for opportunistic exploitation against internet-facing infrastructure.

## Recommendation

- Upgrade LMCache to version 0.5.6 or later immediately to address CVE-2026-107204.
- Apply network segmentation to restrict access to the LMCache /run_script endpoint to known, trusted management IPs.
- Deploy the provided Sigma rule to monitor for suspicious POST requests to the /run_script path.
- Enable web server access logs to audit all requests directed at the LMCache API.
