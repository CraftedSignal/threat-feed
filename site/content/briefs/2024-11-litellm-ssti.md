---
title: LiteLLM Server-Side Template Injection Vulnerability
slug: 2024-11-litellm-ssti
description: A server-side template injection vulnerability in LiteLLM versions 1.80.5 to before 1.83.7 allows authenticated users to execute arbitrary code within the LiteLLM Proxy process via a crafted prompt template, potentially exposing sensitive information and enabling command execution on the host.
date: "2024-11-05T12:00:00Z"
type: advisory
types:
  - advisory
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

A server-side template injection (SSTI) vulnerability has been identified in LiteLLM versions 1.80.5 up to, but not including, 1.83.7. This flaw resides within the `/prompts/test` endpoint, which processes user-supplied prompt templates. Due to insufficient input sanitization, a malicious actor with a valid proxy API key can inject arbitrary code into the template, leading to its execution within the LiteLLM Proxy process. This vulnerability was disclosed on April 24, 2026. Successful exploitation can compromise the proxy's environment, potentially exposing sensitive credentials like provider API keys and database passwords, or allowing arbitrary command execution on the host system. Organizations using affected versions of LiteLLM are at risk. The vulnerability is addressed in version 1.83.7-stable by implementing a sandboxed template renderer.

## Attack Chain

1. An attacker authenticates to the LiteLLM proxy server using a valid API key.
2. The attacker crafts a malicious prompt template containing SSTI payloads.
3. The attacker sends a POST request to the `/prompts/test` endpoint, including the crafted template in the request body.
4. The LiteLLM proxy server receives the request and processes the template without proper sanitization.
5. The SSTI payload executes arbitrary code within the LiteLLM proxy process.
6. The attacker gains access to environment variables containing sensitive information, such as API keys and database credentials.
7. The attacker uses the exposed credentials to gain unauthorized access to external services or data.
8. The attacker executes arbitrary commands on the host system, potentially leading to full system compromise.

## Impact

Successful exploitation of this SSTI vulnerability allows attackers to execute arbitrary code within the LiteLLM Proxy process. This can lead to the exposure of sensitive information such as API keys and database credentials, potentially enabling unauthorized access to other systems and data. Furthermore, attackers can execute arbitrary commands on the host, leading to full system compromise. The impact is significant for organizations relying on LiteLLM for managing and routing AI model requests, as it could result in data breaches, service disruption, and reputational damage.

## Recommendation

*   Upgrade LiteLLM to version `1.83.7-stable` or later to patch the vulnerability, as this version implements a sandboxed template renderer (see Patches).
*   As a temporary workaround, block `POST /prompts/test` at your reverse proxy or API gateway to prevent exploitation attempts (see Workarounds).
*   Review and rotate API keys that should not have access to prompt management routes to limit the potential impact of compromised keys (see Workarounds).
*   Deploy the Sigma rule "Detect LiteLLM SSTI Attempts via /prompts/test" to your SIEM to identify potential exploitation attempts based on HTTP request patterns.
