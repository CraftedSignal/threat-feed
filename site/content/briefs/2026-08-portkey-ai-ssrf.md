---
title: Server-Side Request Forgery in Portkey AI Gateway
slug: 2026-08-portkey-ai-ssrf
description: Portkey AI Gateway through 1.15.2 is vulnerable to SSRF via the /v1/proxy/* route, allowing unauthenticated attackers to query internal services and exfiltrate API keys.
date: "2026-08-28T21:38:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:portkey:ai_gateway:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - api-security
  - cloud
vendors:
  - Portkey AI
products:
  - AI Gateway (<= 1.15.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Portkey AI Gateway through 1.15.2 contains a server-side request forgery vulnerability in the /v1/proxy/* route.
    confidence_band: high
cves:
  - id: CVE-2026-82270
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82270
rules:
  - title: Detect CVE-2026-82270 - SSRF via x-portkey-custom-host header
    description: Detects exploitation of CVE-2026-82270 by monitoring for the presence of the suspicious 'x-portkey-custom-host' header in requests to the /v1/proxy/ endpoint.
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
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Portkey AI Gateway to 1.15.3 or later
      owner: IT Operations
      due: 48h
      evidence: Source states versions through 1.15.2 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF/Load Balancer to block or strip the x-portkey-custom-host header
      owner: Network Security
      addresses: CVE-2026-82270
      evidence: Vulnerability relies on the x-portkey-custom-host header to perform SSRF.
---

Portkey AI Gateway versions 1.15.2 and earlier are affected by a server-side request forgery (SSRF) vulnerability. The flaw exists within the /v1/proxy/* API route, which fails to enforce requestValidator middleware. An attacker can craft malicious HTTP requests that set the 'x-portkey-custom-host' header to point to internal network addresses. When processed, the gateway forwards these requests to the specified internal target. By including Authorization headers in these forged requests, attackers can interact with internal APIs or services not intended for public access. This vulnerability poses a significant risk for the exfiltration of sensitive provider API keys or other internal infrastructure data. Defenders should prioritize patching to version 1.15.3 or later as soon as it becomes available and monitor traffic patterns targeting proxy endpoints.

## Impact

Successful exploitation allows unauthenticated attackers to bypass perimeter security to access internal infrastructure. This can result in the exfiltration of sensitive credentials such as provider API keys, unauthorized access to internal management interfaces, and reconnaissance of the local network environment.

## Recommendation

- Upgrade Portkey AI Gateway to the latest patched version immediately.
- Implement strict ingress filtering and egress controls on the gateway server to limit connections to internal IP ranges (RFC 1918) and sensitive metadata services (e.g., 169.254.169.254).
- Deploy the provided webserver detection rule to identify anomalous header usage associated with this SSRF vector.
