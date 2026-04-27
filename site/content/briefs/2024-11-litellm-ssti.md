---
title: LiteLLM Server-Side Template Injection Vulnerability
slug: 2024-11-litellm-ssti
description: A server-side template injection vulnerability in LiteLLM versions 1.80.5 to before 1.83.7 allows authenticated users to execute arbitrary code within the LiteLLM Proxy process via a crafted prompt template, potentially exposing sensitive information and enabling command execution on the host.
date: "2024-11-05T12:00:00Z"
severities:
  - high
tags:
  - ssti
  - litellm
  - template-injection
  - code-execution
products:
  - LiteLLM
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-xqmj-j6mv-4862
rules:
  - title: Detect LiteLLM SSTI Attempts via /prompts/test
    description: Detects potential server-side template injection attempts targeting the /prompts/test endpoint in LiteLLM.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect LiteLLM SSTI Payload via HTTP Request
    description: Detects HTTP POST requests containing potential SSTI payloads based on common template syntax.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side template injection (SSTI) vulnerability has been identified in LiteLLM versions 1.80.5 up to, but not including, 1.83.7. This flaw resides within the `/prompts/test` endpoint, which processes user-supplied prompt templates. Due to insufficient input sanitization, a malicious actor with a valid proxy API key can inject arbitrary code into the template, leading to its execution within the LiteLLM Proxy process. This vulnerability was disclosed on April 24, 2026. Successful…
