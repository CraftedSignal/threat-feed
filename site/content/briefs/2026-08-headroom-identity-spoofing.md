---
title: Authentication Bypass in Headroom LLM Proxy via Header Spoofing
slug: 2026-08-headroom-identity-spoofing
description: The Headroom LLM proxy improperly derives memory ownership from the unauthenticated 'x-headroom-user-id' request header, allowing attackers to perform unauthorized read and write operations on arbitrary user LLM memory.
date: "2026-08-21T13:24:19Z"
lastmod: "2026-08-21T13:24:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - identity-spoofing
  - cve
  - web-application-vulnerability
  - web-application
  - ssrf
  - vulnerability
vendors:
  - Headroom
products:
  - LLM proxy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The server itself warns about [missing authentication] at startup, so a deployment following the shipped compose exposes the affected data-plane routes to the network without authentication.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A client can therefore name another user's identifier and read or write that user's stored LLM memory.
    confidence_band: high
cves:
  - id: CVE-2026-77776
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77776
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77775
rules:
  - title: Detect CVE-2026-77776 Exploitation - Unauthorized x-headroom-user-id Usage
    description: Detects requests to the LLM proxy where the x-headroom-user-id header is present from external, non-loopback IP addresses.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-77775 Exploitation - SSRF via x-headroom-base-url Header
    description: Detects HTTP requests containing the x-headroom-base-url header pointing to private or reserved IP ranges indicating potential SSRF exploitation
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
    - action: Restrict network access to the Headroom LLM proxy port
      owner: IT Operations
      due: 24h
      evidence: Service exposes the affected data-plane routes to the network without authentication.
  mitigation_plan:
    - priority: immediate
      action: Bind service to 127.0.0.1 and enforce HEADROOM_PROXY_TOKEN
      owner: IT Operations
      addresses: CVE-2026-77776
      evidence: Fix introduces a single resolve_memory_identity seam... the reference docker-compose.yml ships --host 0.0.0.0.
updates:
  - at: "2026-08-21T13:24:29Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-77775 Exploitation - SSRF via x-headroom-base-url Header'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-77775
---

CVE-2026-77776 is an authentication and authorization vulnerability in the Headroom LLM proxy. The application derives memory ownership directly from the 'x-headroom-user-id' HTTP header in 'headroom/proxy/handlers/openai.py' without verifying the caller's identity. This allows an attacker to manipulate the header to impersonate any user, resulting in unauthorized access to sensitive stored LLM memory. 

The risk is significantly amplified by the provided 'docker-compose.yml' file, which defaults to binding the service to '0.0.0.0' and fails to enforce the 'HEADROOM_PROXY_TOKEN' environment variable. When deployed using this configuration, the service exposes its data-plane endpoints to the network, enabling unauthenticated attackers to perform identity spoofing remotely. Defenders must ensure that the proxy is bound to local interfaces only or that the 'HEADROOM_PROXY_TOKEN' is strictly enforced for all inbound requests.

## Impact

Successful exploitation allows unauthenticated attackers to read or write the LLM memory of any user registered within the Headroom instance. This could lead to the exposure of proprietary data, sensitive user conversations, or the injection of malicious context into future LLM interactions, compromising the integrity of all stored assistant memory.

## Recommendation

* Immediately update the 'docker-compose.yml' configuration to bind the proxy to '127.0.0.1' and verify that 'HEADROOM_PROXY_TOKEN' is enabled and non-default.
* Implement network-level access controls to restrict access to the LLM proxy port to authorized internal IP addresses only.
* Patch the Headroom LLM proxy to the version where the 'resolve_memory_identity' seam is introduced in 'headroom/proxy/identity.py'.
* Audit logs for suspicious 'x-headroom-user-id' header patterns that deviate from expected user identification formats.
