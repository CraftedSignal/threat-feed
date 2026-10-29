---
brief_id: brief-2026-10-29-shopify-app-auth-bypass
event_id: brief-2026-10-29-shopify-app-auth-bypass
revision: 1
activity_at: "2026-10-29T18:37:37Z"
title: 'Shopify App: Cross-shop authorization bypass (CVE-2026-63414)'
slug: 2026-10-shopify-app-auth-bypass
description: The shopify_app Ruby gem contains a cross-shop authorization bypass vulnerability where user-supplied shop parameters can override cryptographically verified session contexts.
date: "2026-10-29T18:37:37Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-based vulnerability confirmed
cpes:
  - cpe:2.3:a:shopify:shopify_app:*:*:*:*:*:ruby:*:*
tags:
  - web-application
  - authentication-bypass
  - rubygems
  - cve-2026-63414
vendors:
  - Shopify
products:
  - shopify_app (>= 22.1.0, < 23.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: In affected applications, an attacker with a valid Shopify session token for one shop could send an authenticated request that also supplied a different shop query parameter.
    confidence_band: high
cves:
  - id: CVE-2026-63414
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-6j52-38f8-qhxr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63414
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade shopify_app to 23.0.3
      owner: Development
      due: 48h
      evidence: Remediation section specifies upgrade to version 23.0.3
  hunt_leads:
    - lead: Identify authenticated web requests with mismatched shop parameters
      technique_id: T1190
      data_needed:
        - Web application logs including authenticated session context
        - Shop identifiers from JWT/Session
        - Request parameters
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows for cross-shop context confusion when the shop parameter differs from the session-authenticated shop.
  mitigation_plan:
    - priority: immediate
      action: Implement application-layer 401 enforcement for mismatched shop identifiers
      owner: Development
      addresses: CVE-2026-63414
      evidence: Workarounds section recommends rejecting requests with 401 when requested shop does not match authenticated shop.
---

The `shopify_app` gem (versions 22.1.0 through 23.0.2) is vulnerable to a context confusion flaw in token-exchange authenticated controllers. The helper `current_shopify_domain` inconsistently resolves to a sanitized `shop` query parameter rather than the shop identity derived from a verified Shopify ID token or active session. This allows an authenticated user to perform actions or access data belonging to a different shop by manipulating the `shop` request parameter. 

## Impact
Applications relying on `current_shopify_domain` or `params[:shop]` for authorization, tenant lookup, or access-token selection may suffer from unauthorized access to cross-shop application data or execution of shop-scoped actions. This impact is contingent on the application's internal authorization model and whether it consumes these specific, vulnerable helper methods.

## Recommendation
- Upgrade the `shopify_app` gem to version 23.0.3 or later immediately.
- If immediate patching is not possible, modify controllers to avoid using `params[:shop]` for security-sensitive logic.
- In legacy versions, implement a validation check in token-exchange controllers to ensure the `shop` parameter matches the domain verified in the session or JWT (e.g., `current_shopify_session.shop`), returning a `401 Unauthorized` response on any mismatch.
