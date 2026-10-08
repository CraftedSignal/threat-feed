---
title: CSRF Vulnerability in Pydantic AI Web UI Enables Unauthorized Agent Execution
slug: 2026-10-pydantic-ai-csrf
description: A CSRF vulnerability (CVE-2026-107295) in Pydantic AI web interfaces allows malicious websites to trigger unauthorized agent runs and tool execution on a developer's local machine.
date: "2026-10-08T19:26:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pydantic:pydantic-ai:*:*:*:*:*:*:*:*
tags:
  - web-application
  - csrf
  - pydantic-ai
  - cve-2026-107295
vendors:
  - Pydantic
products:
  - pydantic-ai (>= 1.34.0, < 1.107.4 and >= 2.0.0b1, < 2.28.0)
  - pydantic-ai-slim (>= 1.34.0, < 1.107.4 and >= 2.0.0b1, < 2.28.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: A website visited by a developer can trigger agent runs and server-side tool execution on the local chat endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The endpoint trusts approval decisions relayed by the client, causing the served agent to run and to execute its tools.
    confidence_band: high
cves:
  - id: CVE-2026-107295
    cvss: 7.6
references:
  - https://github.com/advisories/GHSA-h4xc-3qfq-jf93
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107295
action_plan:
  priority: immediate_escalation
  owners:
    - Development Teams
    - Security Operations
  immediate_actions:
    - action: Upgrade pydantic-ai or pydantic-ai-slim to version 1.107.4 or 2.28.0.
      owner: Development Teams
      due: 24h
      evidence: Mitigation section of GHSA-h4xc-3qfq-jf93
  mitigation_plan:
    - priority: immediate
      action: Stop the Pydantic AI web UI when browsing untrusted websites.
      owner: Development Teams
      addresses: CVE-2026-107295
      evidence: Workaround provided in GHSA-h4xc-3qfq-jf93
---

Pydantic AI (pydantic-ai and pydantic-ai-slim) contains a Cross-Site Request Forgery (CSRF) vulnerability, tracked as CVE-2026-107295. The flaw exists in the development web UI provided by `Agent.to_web()` and the `clai web` command. Due to insufficient validation of request headers, the local chat endpoint fails to verify the `Content-Type` of incoming requests. This allows an attacker to host a malicious website that, when visited by a developer with a running Pydantic AI instance, submits unauthorized requests to the local chat server.

Because the service typically binds to localhost, attackers leverage the browser context to reach the loopback interface. This exploit bypasses security controls, including tool execution approval, as the backend incorrectly trusts the request origin. Successful exploitation leads to arbitrary agent execution and local tool invocation with the privileges of the underlying developer process, potentially resulting in data exfiltration or system modification.

## Impact

This vulnerability affects developers and organizations using Pydantic AI for local testing and development. If exploited, an attacker can silently execute code or perform actions via the agent's defined tools on the victim's local machine. This is particularly critical when the agent is configured with tools that possess system-level access, file-write capabilities, or access to sensitive credentials.

## Recommendation

* Upgrade to Pydantic AI version 1.107.4 or 2.28.0 immediately to implement the required `Content-Type: application/json` validation.
* If upgrading is not immediately possible, terminate the Pydantic AI web UI process when browsing untrusted content or when the tool is not in active use.
* Avoid serving agents with side-effecting or high-privilege tools through the development web UI while the instance is accessible via a web browser.
* Audit logs for unexpected POST requests to local development endpoints if using diagnostic web servers.
