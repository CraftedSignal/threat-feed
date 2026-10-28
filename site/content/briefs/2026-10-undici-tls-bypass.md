---
brief_id: brief-2026-10-27-undici-tls-bypass
event_id: brief-2026-10-27-undici-tls-bypass
revision: 1
activity_at: "2026-10-27T23:58:42Z"
title: 'undici: TLS certificate validation bypass in Agent (CVE-2026-109383)'
slug: 2026-10-undici-tls-bypass
description: The undici library fails to enforce custom TLS certificate validation callbacks in Agent constructor options due to a JSON-based cloning mechanism, potentially allowing invalid TLS connections.
date: "2026-10-27T23:58:42Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:nodejs:undici:*:*:*:*:*:node.js:*:*
products:
  - undici (>= 4.0.0, < 6.29.1)
  - undici (>= 7.0.0, < 7.30.1)
  - undici (>= 8.0.0, < 8.12.2)
cves:
  - id: CVE-2026-109383
    cvss: 7.4
    epss: 0.00184
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-2m5v-pch6-74hx
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Team
  immediate_actions:
    - action: Upgrade undici to 6.29.1, 7.30.1, or 8.12.2
      owner: Development Team
      due: 72h
      evidence: Upgrade to undici 6.29.1, 7.30.1, or 8.12.2.
  hunt_leads:
    - lead: Identify applications using undici Agent with custom tls configurations
      technique_id: T1553
      data_needed:
        - Source code audit for undici.Agent instantiation with tls option
        - Static analysis for checkServerIdentity usage in network client configurations
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Only applications that pass a function-valued tls option (such as a custom checkServerIdentity for certificate or public-key pinning) are affected.
  mitigation_plan:
    - priority: immediate
      action: Implement workarounds using connect option instead of tls for Agent
      owner: Development Team
      addresses: CVE-2026-109383
      evidence: Pass the TLS options through connect instead of tls.
---

undici's Agent constructor options undergo a JSON-based deep clone before being passed to origin Pools. Because JSON cannot represent functions, custom TLS check callbacks, such as checkServerIdentity, are silently dropped. This results in the omission of additional security validation for applications relying on custom certificate or public-key pinning. TLS connections will default to standard Node.js hostname and chain verification, bypassing more stringent custom policies defined by developers. This affects common entry points like request and fetch, as well as EnvHttpProxyAgent.

## Impact

Applications implementing custom checkServerIdentity callbacks for enhanced TLS validation are vulnerable. These applications may accept TLS connections that should have been rejected by the custom policy, provided the connection passes standard Node.js default verification.

## Recommendation

- Upgrade undici to version 6.29.1, 7.30.1, or 8.12.2 to resolve the option handling logic.
- Audit applications using undici Agent or EnvHttpProxyAgent that implement TLS configuration, specifically checking for the usage of checkServerIdentity or similar custom verification callbacks.
- As a workaround, developers should pass TLS options through the connect option instead of the tls option for Agent instances, or use requestTls/proxyTls for EnvHttpProxyAgent destinations.
