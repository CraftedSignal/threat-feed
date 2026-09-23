---
title: Unauthenticated API Access in 9router via Reverse Proxy Locality Misconfiguration
slug: 2026-09-9router-auth-bypass
description: 9router versions <= 0.4.80 contain an authentication bypass vulnerability where traffic from a local reverse proxy is incorrectly trusted as local loopback, allowing unauthenticated access to restricted /v1/ APIs.
date: "2026-09-23T19:59:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - api-security
  - webserver
products:
  - 9router (<= 0.4.80)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows unauthenticated remote attackers to access restricted /v1/ API endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-56675
    cvss: 8.3
    epss: 0.00501
references:
  - https://github.com/advisories/GHSA-x5c9-v98j-722r
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56675
rules:
  - title: Detect Unauthenticated Access to 9router API
    description: Detects potential exploitation of CVE-2026-56675 where 9router returns HTTP 200 for /v1/ API paths without an Authorization header.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade 9router instances to version > 0.4.80
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends version fix
  mitigation_plan:
    - priority: immediate
      action: Configure reverse proxy to drop requests to /v1/ without valid Authorization header
      owner: IT Operations
      addresses: CVE-2026-56675
      evidence: Advisory describes bypass due to improper proxy trust
---

9router versions up to 0.4.80 exhibit an authentication bypass vulnerability triggered by the application's reliance on network socket locality to determine API authorization. In a standard reverse-proxy deployment (e.g., using Nginx), the backend identifies all incoming traffic from the proxy as originating from `127.0.0.1`. The application logic interprets this loopback address as a trusted internal client, thereby bypassing the mandatory API key check for all endpoints under the `/v1/` prefix.

This vulnerability impacts any organization deploying 9router behind a reverse proxy that forwards traffic via local loopback. An attacker can perform unauthenticated requests to the `/v1/models` endpoint or, more critically, abuse `/v1/chat/completions` to consume the operator's upstream provider quotas without possessing a valid API key. Because the application logic fails to validate the original client IP despite headers like `X-Forwarded-For`, the bypass remains effective for any non-browser client that does not include an `Origin` header.

## Impact

Successful exploitation allows unauthenticated attackers to enumerate model catalogs and potentially hijack the organization's upstream API provider credentials. This results in direct financial impact due to unauthorized usage of provider quotas and potentially the exposure of sensitive system configuration details. The attack is trivial to execute, requiring only a standard HTTP request to the target proxy port.

## Recommendation

Prioritize patching to version > 0.4.80 to resolve the underlying trust logic flaw. For teams unable to patch immediately, implement strict request filtering at the reverse proxy layer to ensure that only authorized IP addresses or specific request origins are permitted to reach the 9router upstream service.

* Upgrade 9router to a version later than 0.4.80 immediately.
* Configure the reverse proxy (e.g., Nginx) to enforce API key validation or block requests to `/v1/*` that lack required authentication headers at the edge, rather than relying on the backend's internal trust model.
* Monitor web server access logs for repeated HTTP 200 responses to `/v1/*` endpoints originating from untrusted external IPs.
