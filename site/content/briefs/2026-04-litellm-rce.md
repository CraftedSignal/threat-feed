---
title: LiteLLM Remote Code Execution via Bytecode Rewriting (CVE-2026-40217)
slug: 2026-04-litellm-rce
description: LiteLLM through 2026-04-08 allows remote attackers to execute arbitrary code via bytecode rewriting at the /guardrails/test_custom_code URI, potentially leading to complete system compromise.
date: "2026-04-11T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-40217
  - litellm
  - rce
  - bytecode-rewriting
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-40217
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40217
  - https://www.x41-dsec.de/lab/advisories/x41-2026-001-litellm/
rules:
  - title: Detect LiteLLM Bytecode Rewrite Attempt
    description: Detects potential attempts to exploit CVE-2026-40217 by monitoring POST requests to the /guardrails/test_custom_code URI.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of Errors from LiteLLM Endpoint
    description: Detects potential exploitation attempts by monitoring for a high volume of server errors originating from requests to the /guardrails/test_custom_code endpoint.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

LiteLLM, a library for simplifying interactions with Large Language Models (LLMs), is vulnerable to remote code execution (RCE) through version 2026-04-08. The vulnerability, identified as CVE-2026-40217, exists due to insufficient input validation at the `/guardrails/test_custom_code` URI. A remote attacker can exploit this flaw by rewriting bytecode, effectively injecting and executing arbitrary code on the server hosting LiteLLM. This vulnerability poses a significant risk, as it allows unauthenticated attackers with network access to the affected server to gain complete control.

## Attack Chain

1.  An attacker identifies a LiteLLM instance running a vulnerable version (<= 2026-04-08) with the `/guardrails/test_custom_code` endpoint exposed.
2.  The attacker crafts a malicious HTTP request targeting the `/guardrails/test_custom_code` URI.
3.  The malicious request includes specially crafted data designed to rewrite the bytecode executed by the LiteLLM instance.
4.  The LiteLLM application, due to the vulnerability, processes the attacker-supplied data without proper sanitization or validation.
5.  The application rewrites its own bytecode based on the attacker's input.
6.  The rewritten bytecode contains malicious code injected by the attacker.
7.  The application executes the rewritten bytecode, effectively executing the attacker's injected code.
8.  The attacker gains arbitrary code execution on the server, allowing them to compromise the system, install malware, or exfiltrate data.

## Impact

Successful exploitation of CVE-2026-40217 allows unauthenticated remote attackers to execute arbitrary code on systems running vulnerable versions of LiteLLM. This can lead to complete system compromise, including data theft, ransomware deployment, and denial of service. The vulnerability could affect any organization utilizing LiteLLM for LLM interaction, particularly those exposing the vulnerable endpoint to untrusted networks. The impact is rated as critical due to the ease of exploitation and the potential for widespread damage.

## Recommendation

*   Apply the necessary patches or upgrade to a version of LiteLLM that addresses CVE-2026-40217 immediately.
*   Implement network segmentation to restrict access to the `/guardrails/test_custom_code` endpoint, as referenced in the vulnerability description.
*   Deploy the provided Sigma rule `Detect LiteLLM Bytecode Rewrite Attempt` to identify potential exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious POST requests to the `/guardrails/test_custom_code` URI, using the log source specified in the Sigma rule.
