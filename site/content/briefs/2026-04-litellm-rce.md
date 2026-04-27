---
title: LiteLLM Remote Code Execution via Bytecode Rewriting (CVE-2026-40217)
slug: 2026-04-litellm-rce
description: LiteLLM through 2026-04-08 allows remote attackers to execute arbitrary code via bytecode rewriting at the /guardrails/test_custom_code URI, potentially leading to complete system compromise.
date: "2026-04-11T12:00:00Z"
severities:
  - critical
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

LiteLLM, a library for simplifying interactions with Large Language Models (LLMs), is vulnerable to remote code execution (RCE) through version 2026-04-08. The vulnerability, identified as CVE-2026-40217, exists due to insufficient input validation at the `/guardrails/test_custom_code` URI. A remote attacker can exploit this flaw by rewriting bytecode, effectively injecting and executing arbitrary code on the server hosting LiteLLM. This vulnerability poses a significant risk, as it allows…
