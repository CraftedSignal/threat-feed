---
brief_id: brief-2026-05-litellm-cmd-injection
event_id: brief-2026-05-litellm-cmd-injection
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:a76845026c6a84f7385b5ee12e8be406ebbd3bbd6452253b74b7c1f3a60db57c
    summary: exploited:true; KEV CVE-2026-42271; KEV CVE-2026-48710; KEV CVE-2026-42208
    changed_fields:
      - affected_products
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: LiteLLM Authenticated Command Injection via MCP stdio Test Endpoints (CVE-2026-42271)
slug: 2026-05-litellm-cmd-injection
description: A command injection vulnerability exists in LiteLLM versions 1.74.2 to < 1.83.7, allowing authenticated users with a valid API key to execute arbitrary OS commands as root via the MCP stdio transport through the `POST /mcp-rest/test/connection` and `POST /mcp-rest/test/tools/list` endpoints, especially in default Docker deployments, and a public exploit is available.
date: "2026-05-20T02:01:38Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-05-08T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:encode:starlette:*:*:*:*:*:python:*:*
  - cpe:2.3:a:litellm:litellm:*:*:*:*:*:*:*:*
has_poc: true
tags:
  - command injection
  - rce
  - litellm
  - CVE-2026-42271
vendors:
  - BerriAI
products:
  - LiteLLM
  - LiteLLM (>= 1.74.2 < 1.83.7)
  - Starlette
product_versions:
  - product: Starlette
    range: <= 1.0.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
cves:
  - id: CVE-2026-42271
    cvss: 8.8
    epss: 0.60784
    kev: true
    kev_status: "true"
  - id: CVE-2026-48710
    cvss: 6.5
    epss: 0.00353
    kev: true
    kev_status: "true"
  - id: CVE-2026-42208
    cvss: 9.8
    epss: 0.6259
    kev: true
    kev_status: "true"
references:
  - https://sploitus.com/exploit?id=47564AB3-627D-51FA-A9A8-571279747153&utm_source=rss&utm_medium=rss
  - https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g
  - https://advisories.gitlab.com/pypi/litellm/CVE-2026-42271/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42271
  - https://github.com/BerriAI/litellm/releases/tag/v1.83.7-stable
  - https://docs.litellm.ai/docs/mcp
  - https://thehackernews.com/2026/06/litellm-flaw-cve-2026-42271-exploited.html
rules:
  - title: Detect CVE-2026-42271 Exploitation Attempt — LiteLLM MCP Stdio Command Injection
    description: Detects CVE-2026-42271 exploitation attempt — POST request to /mcp-rest endpoints with stdio transport and suspicious command arguments
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-42271 Post-Exploitation — File Creation in /tmp
    description: Detects CVE-2026-42271 post-exploitation activity by detecting file creation in /tmp directory by the webserver process
    platform: sigma
    severity: medium
    tactics:
      - execution
      - post_exploitation
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-06-14T08:48:45Z"
    level: L2
    summary: poc_available; added CVE-2026-42208 +1; litellm version >= 1.74.2 < 1.83.7
    sources:
      - the-hacker-news
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-42271; KEV CVE-2026-48710; KEV CVE-2026-42208
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

A command injection vulnerability, tracked as CVE-2026-42271, affects LiteLLM versions 1.74.2 up to, but not including, 1.83.7. The vulnerability resides in the MCP (Message Connector Protocol) stdio transport and can be exploited through the `/mcp-rest/test/connection` and `/mcp-rest/test/tools/list` endpoints. An attacker with a valid API key can leverage this flaw to execute arbitrary operating system commands with root privileges within the Docker container, which is the default deployment. The availability of a public exploit on Sploitus significantly increases the risk to unpatched LiteLLM instances. A proof-of-concept exploit, along with mitigation steps, is documented in the advisory.

## Attack Chain

1.  An attacker obtains a valid LiteLLM API key.
2.  The attacker sends a POST request to `/mcp-rest/test/connection` or `/mcp-rest/test/tools/list`.
3.  The request body specifies `"transport": "stdio"` to enable the vulnerable transport.
4.  The request body includes a `"command"` field, set to a common shell executable such as `bash`.
5.  The request body includes an `"args"` array containing shell arguments crafted to execute arbitrary commands (e.g., `"-c", "id > /tmp/pwned"`).
6.  The LiteLLM server spawns a subprocess using the provided command and arguments.
7.  The attacker-controlled command executes with root privileges inside the Docker container.
8.  The attacker achieves arbitrary command execution, potentially leading to data exfiltration, reverse shell establishment, or persistence.

## Impact

Successful exploitation of this command injection vulnerability allows an attacker to execute arbitrary commands with root privileges on the affected LiteLLM instance. In a default Docker deployment, this provides complete control over the container, leading to potential data exfiltration, deployment of malware, or further lateral movement within the network. The vulnerability impacts any LiteLLM instances running versions between 1.74.2 and 1.83.6 that have not applied the necessary patches or mitigations.

## Recommendation

*   Upgrade LiteLLM to version 1.83.7 or later to apply the command whitelist and role-based access control fixes (CVE-2026-42271).
*   Implement a reverse proxy rule to block access to the `/mcp-rest/test/connection` and `/mcp-rest/test/tools/list` endpoints.
*   Rotate API keys and restrict their privileges to minimize the impact of potential key compromise.
*   Deploy LiteLLM in a Docker container with a non-root user context (`docker run --user 1000:1000 ...`).
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts targeting these endpoints.
