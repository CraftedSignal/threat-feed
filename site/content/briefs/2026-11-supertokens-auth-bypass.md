---
brief_id: brief-2026-11-09-supertokens-auth-bypass
event_id: brief-2026-11-09-supertokens-auth-bypass
revision: 1
activity_at: "2026-11-09T19:57:27Z"
title: 'SuperTokens Core: Authentication bypass via API-key and tenant enforcement (CVE-2026-123797)'
slug: 2026-11-supertokens-auth-bypass
description: SuperTokens Core versions prior to 11.3.6, 11.4.6, and 12.0.8 are vulnerable to an authentication bypass that allows unauthenticated role management due to improper handling of tenant paths and CDI versions.
date: "2026-11-09T19:57:27Z"
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
cpes:
  - cpe:2.3:a:supertokens:supertokens_core:*:*:*:*:*:*:*:*
vendors:
  - SuperTokens
products:
  - SuperTokens Core (< 11.3.6, 11.4.6, 12.0.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated caller able to reach the Core endpoint can therefore use PUT /ghosttenant/recipe/role and GET /ghosttenant/recipe/roles to create and enumerate application roles without a valid API key.
    confidence_band: high
cves:
  - id: CVE-2026-123797
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123797
rules:
  - title: Detect Potential CVE-2026-123797 Exploitation - Role Management Bypass
    description: Detects requests to the SuperTokens Core API involving the /ghosttenant/ path, which is associated with CVE-2026-123797 authentication bypass.
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade SuperTokens Core to 11.3.6, 11.4.6, or 12.0.8
      owner: IT Operations
      due: 24h
      evidence: This issue is fixed in versions 11.3.6, 11.4.6, and 12.0.8.
  hunt_leads:
    - lead: Search web access logs for /ghosttenant/ URIs
      technique_id: T1190
      data_needed:
        - Web server URI access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An unauthenticated caller able to reach the Core endpoint can therefore use PUT /ghosttenant/recipe/role and GET /ghosttenant/recipe/roles
  mitigation_plan:
    - priority: immediate
      action: Upgrade SuperTokens Core to 11.3.6 or later
      owner: IT Operations
      addresses: CVE-2026-123797
      evidence: This issue is fixed in versions 11.3.6, 11.4.6, and 12.0.8.
---

SuperTokens Core contains an authentication bypass vulnerability (CVE-2026-123797) affecting versions prior to 11.3.6, 11.4.6, and 12.0.8. An unauthenticated attacker capable of reaching the Core endpoint can use unknown tenant paths combined with older supported CDI versions to bypass API-key and public-tenant enforcement. This occurs because the `checkIPAccess` and `assertThatAPIKeyCheckPasses` functions suppress `TenantOrAppNotFoundException`, and the public-tenant guard only applies to CDI versions 5.0 and later.

## Impact

Successful exploitation allows an unauthenticated attacker to create and enumerate application roles by sending crafted requests to the Core API, such as `PUT /ghosttenant/recipe/role` and `GET /ghosttenant/recipe/roles`.

## Recommendation

* Patch SuperTokens Core by upgrading to versions 11.3.6, 11.4.6, or 12.0.8 immediately.
* Audit access logs for requests involving `/ghosttenant/` or unconventional tenant paths targeting role management endpoints.
* Restrict network access to the SuperTokens Core API endpoint to trusted infrastructure only.
