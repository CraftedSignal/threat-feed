---
brief_id: brief-2026-11-10-gpustack-saml-bypass
event_id: brief-2026-11-10-gpustack-saml-bypass
revision: 1
activity_at: "2026-11-10T16:34:10Z"
title: 'GPUStack: SAML callback authentication bypass (CVE-2026-102894)'
slug: 2026-11-gpustack-saml-bypass
description: GPUStack versions 0.7.1 through 2.2.1 are vulnerable to an authentication bypass in the /auth/saml/callback endpoint, allowing unauthenticated attackers to assume arbitrary identities, including administrator accounts, by submitting forged SAML assertions.
date: "2026-11-10T16:34:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:gpustack:gpustack:*:*:*:*:*:*:*:*
vendors:
  - GPUStack
products:
  - GPUStack (>= 0.7.1, < 2.2.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The callback processes the payload and issues a session regardless of whether SAML is set up, so every deployment is affected.
    confidence_band: high
cves:
  - id: CVE-2026-102894
    cvss: 9.1
    epss: 0.00259
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-62m9-f875-rqw6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102894
rules:
  - title: Detect CVE-2026-102894 Exploitation - Unauthorized Access to SAML Callback
    description: Detects potential exploitation of the GPUStack SAML callback by identifying HTTP POST requests to the vulnerable endpoint.
    platform: sigma
    severity: critical
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
    - Detection Engineering
  immediate_actions:
    - action: Patch GPUStack to 2.2.2 or later
      owner: IT Operations
      due: 24h
      evidence: Fixed in gpustack 2.2.2
    - action: Block network access to /auth/saml/callback at ingress/proxy
      owner: IT Operations
      due: 24h
      evidence: block network access to /auth/saml/callback
  hunt_leads:
    - lead: Identify successful POST requests to /auth/saml/callback from unauthorized or unusual source IPs
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The callback processes the payload and issues a session regardless of whether SAML is set up
  mitigation_plan:
    - priority: immediate
      action: Upgrade to GPUStack 2.2.2
      owner: IT Operations
      addresses: CVE-2026-102894
      evidence: Fixed in gpustack 2.2.2
---

GPUStack versions 0.7.1 through 2.2.1 contain a critical authentication bypass vulnerability due to improper handling of SAML assertions. The application fails to verify the SAML response signature, issuer, audience, destination, or time conditions using the expected `OneLogin_Saml2_Auth.process_response()` function. This vulnerability is active regardless of whether SAML SSO is configured, allowing an attacker to reach the `/auth/saml/callback` endpoint and authenticate as any user by posting a forged XML payload. Successful exploitation results in account takeover, including administrative access, and allows for infinite replay of captured assertions.

## Impact

Successful exploitation grants an attacker full access to the target GPUStack deployment and any managed infrastructure. The vulnerability allows for identity spoofing of existing administrative users. Because the affected endpoint is enabled by default, all installations prior to 2.2.2 are at risk.

## Recommendation

- Upgrade GPUStack to version 2.2.2 or later immediately to patch CVE-2026-102894.
- Until patching, block network access to the `/auth/saml/callback` URI at the reverse proxy or ingress level.
- Audit existing user sessions and logs for anomalous successful authentication events originating from unexpected or untrusted network sources.
