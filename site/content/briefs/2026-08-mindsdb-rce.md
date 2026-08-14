---
title: Unauthenticated Remote Code Execution in MindsDB Minds Platform
slug: 2026-08-mindsdb-rce
description: MindsDB Minds Platform versions 26.1.0 and earlier are vulnerable to unauthenticated remote code execution via insecure handling of LLM prompts and unsandboxed scratchpad execution.
date: "2026-08-14T20:12:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - MindsDB
products:
  - Minds Platform (26.1.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The scratchpad tool calls exec() on attacker-influenced Python source without sandboxing.
    confidence_band: high
cves:
  - id: CVE-2026-73678
    cvss: 10
rules:
  - title: Detects CVE-2026-73678 Exploitation - Unauthenticated RCE via MindsDB API
    description: Detects attempts to configure settings and trigger agent responses via unauthenticated endpoints as part of the CVE-2026-73678 exploit chain.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.006
    data_sources:
      - webserver
rules_count: 1
---

MindsDB Minds Platform version 26.1.0 and earlier contains an unauthenticated remote code execution vulnerability (CVE-2026-73678). The flaw exists within the Anton agent's scratchpad tool, which fails to sandbox Python code before execution via the exec() function. An unauthenticated attacker can leverage this by first modifying the application settings to use an attacker-controlled LLM API key via the PUT /api/v1/settings/ endpoint. Following this, the attacker sends a crafted prompt to the POST /api/v1/responses/ endpoint. This prompt forces the Anton agent to use the scratchpad tool to run arbitrary Python code. Because the application process lacks sandboxing, the attacker achieves OS command execution with the privileges of the user running the MindsDB application. This vulnerability allows for full system compromise, including the exfiltration of sensitive files such as SSH keys, stored credentials, and local environment secrets.

## Attack Chain

1. Attacker identifies an internet-facing MindsDB Minds Platform instance version 26.1.0 or earlier.
2. Attacker sends an unauthenticated PUT request to /api/v1/settings/ to inject a custom LLM API key.
3. Attacker sends an unauthenticated POST request to /api/v1/responses/ containing a prompt designed to trigger the Anton agent.
4. The Anton agent processes the prompt and invokes the vulnerable scratchpad tool.
5. The scratchpad tool executes the attacker-provided Python code using the insecure exec() call.
6. Arbitrary OS commands are executed in the context of the user running the MindsDB application.
7. Attacker performs post-exploitation activities, including credential harvesting and environment secret access.

## Impact

Successful exploitation results in full remote code execution on the host running the MindsDB Minds Platform. An attacker can gain access to the host file system, including SSH keys, stored credentials, and environment variables. This impact applies to any deployment where the MindsDB Platform is exposed to unauthenticated network access, affecting Windows, macOS, and Linux environments.

## Recommendation

* Update MindsDB Minds Platform to a patched version beyond 26.1.0 immediately.
* Restrict network access to the MindsDB API endpoints, specifically /api/v1/settings/ and /api/v1/responses/, to trusted internal management subnets.
* Monitor web server access logs for anomalous PUT requests to /api/v1/settings/ followed by suspicious POST requests to /api/v1/responses/.
* Deploy the Sigma rule below to identify potential exploitation attempts targeting these endpoints.
