---
title: IBM Langflow OSS Unauthenticated Remote Code Execution via Chained API Endpoints (CVE-2026-9198)
slug: 2026-07-ibm-langflow-oss-rce
description: Unauthenticated attackers can achieve Remote Code Execution (RCE) on default IBM Langflow OSS deployments, versions 1.0.0 through 1.10.0, by chaining access to the `/api/v1/auto_login` endpoint, which mints SUPERUSER tokens, with the `/api/v1/validate/code` endpoint, which executes user-supplied code via `exec()`.
date: "2026-07-17T18:18:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - api-exploitation
  - unauthenticated-access
  - code-injection
  - web-vulnerability
  - ai-llm
vendors:
  - IBM
products:
  - Langflow OSS (1.0.0 - 1.10.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM Langflow OSS ... allows unauthenticated attackers to chain /api/v1/auto_login ... to achieve full RCE
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: /api/v1/validate/code (executes user code via exec()) to achieve full RCE
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: /api/v1/auto_login (mints SUPERUSER tokens to any network caller)
    confidence_band: high
cves:
  - id: CVE-2026-9198
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9198
  - https://www.ibm.com/support/pages/node/7278927
rules:
  - title: Detects CVE-2026-9198 Exploitation - Langflow OSS RCE Attempt
    description: Detects CVE-2026-9198 exploitation attempts targeting IBM Langflow OSS via suspicious calls to the `/api/v1/validate/code` endpoint, indicating potential remote code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - webserver
rules_count: 1
---

IBM Langflow OSS, an open-source framework for building and deploying AI/LLM applications, contains a critical vulnerability (CVE-2026-9198) affecting versions 1.0.0 through 1.10.0. This flaw allows unauthenticated attackers to achieve full Remote Code Execution (RCE) on default installations. The exploitation involves a two-step chaining process: first, an attacker leverages the `/api/v1/auto_login` endpoint to obtain SUPERUSER tokens without authentication; second, these tokens are then used to invoke the `/api/v1/validate/code` endpoint, which insecurely executes arbitrary user-provided code using Python's `exec()` function. This vulnerability bypasses authentication, granting an attacker complete control over the compromised Langflow instance and its underlying system, posing a severe risk to data integrity, confidentiality, and system availability.

## Attack Chain

1. **Reconnaissance:** An attacker identifies an internet-facing IBM Langflow OSS instance vulnerable to CVE-2026-9198.
2. **Unauthenticated Token Minting:** The attacker sends an unauthenticated HTTP request to the `/api/v1/auto_login` endpoint on the vulnerable Langflow server.
3. **SUPERUSER Token Acquisition:** Due to the vulnerability, the Langflow server issues a SUPERUSER authentication token to the unauthenticated attacker.
4. **Malicious Code Crafting:** The attacker prepares a malicious Python code payload designed to execute arbitrary commands on the target system.
5. **Authenticated Code Execution Request:** Using the newly acquired SUPERUSER token for authentication, the attacker sends an HTTP POST request to the `/api/v1/validate/code` endpoint. The malicious Python code payload is embedded within this request, likely in the request body or specific query parameters.
6. **Code Injection and Execution:** The `/api/v1/validate/code` endpoint, lacking proper input validation and sanitization, directly executes the provided Python code using the `exec()` function.
7. **Remote Code Execution:** The attacker's arbitrary commands are executed on the underlying operating system, resulting in full Remote Code Execution (RCE).
8. **Post-Exploitation:** The attacker gains complete control over the Langflow server, potentially leading to data exfiltration, system compromise, or further lateral movement within the victim's network.

## Impact

Successful exploitation of CVE-2026-9198 leads to immediate and complete compromise of the affected IBM Langflow OSS instance. This allows unauthenticated attackers to execute arbitrary code on the server, granting them full control over the system. The impact includes severe data breaches, disruption of services, and the ability for attackers to establish persistence or pivot to other systems within the network. Since Langflow instances can manage critical AI/LLM workflows and sensitive data, the compromise could expose proprietary models, training data, and intellectual property, leading to significant financial and reputational damage for affected organizations. The vulnerability affects all default deployments of Langflow OSS versions 1.0.0 through 1.10.0.

## Recommendation

* **Patch CVE-2026-9198:** Immediately apply patches or upgrade IBM Langflow OSS to a version beyond 1.10.0 that addresses CVE-2026-9198. Refer to the IBM security advisory at `https://www.ibm.com/support/pages/node/7278927`.
* **Deploy the Sigma rule:** Deploy the provided Sigma rule `Detects CVE-2026-9198 Exploitation - Langflow OSS RCE Attempt` to your SIEM and tune for your environment to detect suspicious activity related to the `/api/v1/validate/code` endpoint.
* **Enable webserver logging:** Ensure comprehensive webserver logging is enabled, capturing `cs-uri-stem`, `cs-uri-query`, `cs-method`, and ideally, relevant portions of POST request bodies, to activate and enhance the effectiveness of the detection rule.
