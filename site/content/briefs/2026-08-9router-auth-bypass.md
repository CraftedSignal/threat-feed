---
title: 9router Authentication Bypass and SSRF via Host Header Spoofing
slug: 2026-08-9router-auth-bypass
description: An authentication bypass in 9router 0.4.80 and earlier allows remote attackers to spoof the 'Host' header, gaining unauthorized access to API proxy endpoints, enabling quota theft via AI relay and server-side request forgery (SSRF).
date: "2026-08-28T21:15:37Z"
lastmod: "2026-08-28T21:15:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:9router:9router:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - ssrf
  - api-security
  - web-vulnerability
  - authorization-bypass
  - llm-proxy
vendors:
  - 9router
products:
  - 9router (<= 0.4.80)
  - 9router (< 0.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The application incorrectly trusts the Host header, allowing unauthenticated remote attackers to access the /v1 API proxy.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: This results in an open AI relay that can abuse the victim's stored API keys.
    confidence_band: high
cves:
  - id: CVE-2026-55641
    cvss: 8.2
    epss: 0.00323
references:
  - https://github.com/advisories/GHSA-86m2-fcxq-5q7c
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55641
  - https://github.com/advisories/GHSA-8gmq-j984-vp4r
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55638
rules:
  - title: Detect Suspicious Host Header Spoofing Attempting 9router Bypass
    description: Detects HTTP requests to potential 9router endpoints where the Host header is 'localhost' or '127.0.0.1' but originates from an external network source.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-55638 Exploitation - Unauthorized LLM Proxy Access via /codex
    description: Detects exploitation attempts against CVE-2026-55638 by monitoring for POST requests to the /codex/ endpoint which bypasses intended authorization gates.
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
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all instances of 9router to 0.5.2 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-55641 patch requirement
  hunt_leads:
    - lead: Search web logs for 200 OK responses to /v1/ routes originating from non-loopback IPs
      technique_id: T1190
      data_needed:
        - c-ip
        - sc-status
        - cs-uri-stem
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source evidence of bypass granting full /v1 access
  mitigation_plan:
    - priority: immediate
      action: Bind 9router to 127.0.0.1 if currently bound to 0.0.0.0.
      owner: IT Operations
      addresses: CVE-2026-55641
      evidence: Source documentation of binding exposure
updates:
  - at: "2026-08-28T21:15:48Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-55638 Exploitation - Unauthorized LLM Proxy Access via /codex'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-8gmq-j984-vp4r
---

9router versions 0.4.80 and earlier contain a critical authentication bypass vulnerability (CVE-2026-55641) located in the application's request guard logic. The `isLocalRequest` function determines if a request should be exempt from API authentication by inspecting the client-controlled `Host` header rather than the actual socket peer address. Because 9router defaults to binding to `0.0.0.0` (all interfaces) while misleadingly reporting the service as bound to "localhost," remote attackers can reach the service and spoof `Host: localhost` to be treated as local users. 

This bypass grants unauthenticated access to the `/v1` proxy. Attackers can leverage this to exhaust the victim's paid AI provider quotas (AI relay) or conduct SSRF attacks. The SSRF primitive is particularly severe as the `/v1/search` endpoint allows arbitrary configuration of the outbound `baseUrl` via request parameters, enabling attackers to target internal services or cloud metadata endpoints and receive the response directly in the JSON output. The issue is exacerbated by default settings that lack mandatory API key requirements for non-loopback traffic.

## Attack Chain

1. Attacker identifies an internet-facing 9router instance listening on port 20128.
2. Attacker sends a specially crafted HTTP request to the target `/v1/search` or `/v1/messages` endpoint.
3. Attacker sets the HTTP `Host` header to `localhost` to bypass the `isLocalRequest` guard check.
4. 9router middleware incorrectly validates the request as originating from a local source due to the spoofed header.
5. The application grants the request bypass-level access, skipping the `hasValidApiKey` check.
6. For search requests, the attacker injects an arbitrary `baseUrl` (e.g., `http://169.254.169.254/`) via the `provider_options` body parameter.
7. 9router's `handleSearchCore` performs a server-side `fetch` to the attacker-supplied URL.
8. The JSON response from the internal resource is reflected back to the attacker, completing the SSRF or unauthorized relay chain.

## Impact

Successful exploitation allows remote, unauthenticated attackers to perform unauthorized actions on behalf of the victim. This results in the depletion of financial credits or usage quotas on connected AI provider accounts, the potential exfiltration of prompts and data via the AI relay, and the ability to map internal networks or exfiltrate cloud metadata via the SSRF primitive. Any deployment of 9router reachable over a network is vulnerable to this attack.

## Recommendation

1. Upgrade to 9router version 0.5.2 or later immediately to patch the authentication logic.
2. If an immediate upgrade is not possible, modify the 9router configuration to bind only to `127.0.0.1` and ensure it is not reachable from untrusted networks.
3. Implement network-level access control (firewall or VPN) to restrict access to port 20128 to known, authorized IP addresses.
4. Enable mandatory API key authentication for all requests in the 9router settings, regardless of perceived request origin.
5. Use the provided POC methods against lab environments to verify that incoming requests are correctly rejected when the `Host` header does not match the actual connection source.
