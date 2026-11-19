---
brief_id: brief-2026-05-28-starlette-auth-bypass
event_id: brief-2026-05-28-starlette-auth-bypass
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:d3517c943346a3f3941577dc80486bd7022d7bbf770febc039e734d5cc571af2
    summary: exploited:true; KEV CVE-2026-48710
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Starlette Framework Authentication Bypass Vulnerability (CVE-2026-48710)
slug: 2026-05-starlette-auth-bypass
description: CVE-2026-48710, also known as BadHost, is an authentication bypass vulnerability affecting the Starlette framework before version 1.0.1, and related frameworks like FastAPI, vLLM, and LiteLLM, due to a lack of input sanitization on host header paths, potentially allowing attackers to access sensitive data and steal credentials.
date: "2026-05-28T16:32:49Z"
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
  observed_at: "2026-09-02T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:encode:starlette:*:*:*:*:*:python:*:*
tags:
  - authentication bypass
  - web application
  - asgi
vendors:
  - Kludex
products:
  - FastAPI
  - LiteLLM
  - Starlette
  - Starlette framework
  - vLLM
product_versions:
  - product: FastAPI
    range: < 1.0.1
  - product: LiteLLM
    range: < 1.0.1
  - product: Starlette
    range: < 1.0.1
  - product: Starlette framework
    range: < 1.0.1
  - product: vLLM
    range: < 1.0.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-48710
    cvss: 6.5
    epss: 0.02099
    kev: true
    kev_status: "true"
references:
  - https://ccb.belgium.be/advisories/warning-vulnerability-starlette-framework-and-related-frameworks-fastapi-exposes
  - https://badhost.org/
  - https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr
  - https://ostif.org/disclosing-the-badhost-vulnerability-in-starlette/
  - https://x41-dsec.de/lab/advisories/x41-2026-002-starlette/
  - https://arstechnica.com/information-technology/2026/05/millions-of-ai-agents-imperiled-by-critical-vulnerability-in-open-source-package/
  - https://www.cve.org/CVERecord?id=CVE-2026-48710
rules:
  - title: Detects CVE-2026-48710 Exploitation — Suspicious Host Header Manipulation
    description: Detects CVE-2026-48710 exploitation attempts by monitoring for unusual characters or patterns in the Host header of HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-48710 Exploitation — HTTP Request to Sensitive Endpoint with Shell Metacharacters in Host Header
    description: Detects CVE-2026-48710 exploitation attempt with shell metacharacters in the host header to access sensitive endpoints
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-09-02T17:56:10Z"
    level: L2
    summary: fastapi version < 1.0.1; vllm version < 1.0.1; litellm version < 1.0.1; starlette framework version < 1.0.1
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-48710
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-48710
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

The "BadHost" vulnerability, tracked as CVE-2026-48710, impacts the Starlette framework (versions prior to 1.0.1), a widely used ASGI implementation underpinning numerous AI agents and tools. This framework serves as the base for FastAPI, vLLM, LiteLLM, and thousands of other open-source projects. The vulnerability stems from a lack of input sanitization on host header paths, allowing attackers to bypass authentication mechanisms. Given the widespread adoption of Starlette and the relative ease of exploitation, this vulnerability presents a significant risk, potentially leading to the exposure of sensitive data, credential theft (including third-party accounts), and supply chain attacks.

## Attack Chain

1. The attacker sends a crafted HTTP request to a Starlette-based application.
2. The attacker manipulates the Host header in the HTTP request to include malicious characters or unexpected paths.
3. Due to missing sanitization, Starlette reconstructs the `request.url` based on the malformed Host header.
4. The reconstructed `request.url.path` differs from the intended path based on the raw HTTP path.
5. Authentication middleware or endpoint security checks relying on `request.url` are bypassed.
6. The attacker gains unauthorized access to sensitive data or restricted functionality.
7. The attacker may exfiltrate stolen credentials for third-party accounts stored in MCP servers.
8. The attacker leverages compromised credentials for supply chain attacks.

## Impact

The BadHost vulnerability (CVE-2026-48710) affects millions of servers utilizing the Starlette framework and related projects. Successful exploitation can lead to authentication bypass, allowing attackers to access sensitive data, steal credentials, and potentially launch supply chain attacks. The targeted sectors are broad due to the widespread adoption of Starlette in building various applications, including AI agents, web services, and management UIs. The vulnerability can expose credentials for third-party accounts stored in MCP servers, further amplifying the potential damage.

## Recommendation

*   Apply the patch to upgrade Starlette to version 1.0.1 or later to address CVE-2026-48710 immediately after thorough testing.
*   Deploy a reverse proxy in front of your ASGI server to validate and normalize the Host header before forwarding requests, mitigating the attack vector.
*   If using middleware, utilize `scope["path"]` instead of `request.url.path` to avoid relying on the reconstructed URL, as recommended in the advisory.
*   Monitor web server logs for suspicious Host header manipulations and unusual request patterns to detect potential exploitation attempts using the provided Sigma rule.
