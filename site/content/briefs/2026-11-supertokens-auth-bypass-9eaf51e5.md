---
brief_id: brief-2026-11-10-supertokens-auth-bypass-9eaf51e5
event_id: brief-2026-11-10-supertokens-auth-bypass-9eaf51e5
revision: 1
activity_at: "2026-11-10T02:08:24Z"
title: 'SuperTokens Core: Authorization bypass in Multitenancy module (CVE-2026-123800)'
slug: 2026-11-supertokens-auth-bypass-9eaf51e5
description: SuperTokens Core contains an authorization bypass vulnerability (CVE-2026-123800) allowing an attacker with a valid tenant API key to modify parent connection URIs and base tenant configurations, leading to potential cross-tenant account takeover and persistence.
date: "2026-11-10T02:08:24Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:supertokens:core:*:*:*:*:*:*:*:*
vendors:
  - SuperTokens
products:
  - SuperTokens Core (>= 6.0.0, < 12.3.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: an attacker holding one application valid API key can update the parent domain because the CUD-target branch checks the domain without requiring the source application and tenant to be public.
    confidence_band: high
cves:
  - id: CVE-2026-123800
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123800
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch SuperTokens Core to version 12.3.1 or the relevant fixed version for your branch
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-123800 remediation advice
  hunt_leads:
    - lead: Identify unauthorized updates to tenant connection URIs or modifications to base tenant configuration
      technique_id: T1548
      data_needed:
        - SuperTokens application logs for API calls to multitenancy endpoints
        - Audit logs showing changes to auth factor flags or api_keys
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: attacker can replace the parent key and then sibling application keys, read or modify sibling users
  mitigation_plan:
    - priority: immediate
      action: Upgrade SuperTokens Core to the latest patched release
      owner: IT Operations
      addresses: CVE-2026-123800
      evidence: Fixed versions listed in NVD entry
---

SuperTokens Core, an open-source authentication server, is affected by an authorization bypass vulnerability (CVE-2026-123800) in the `Multitenancy.checkPermissionsForCreateOrUpdate` function. The vulnerability stems from inadequate authorization checks when processing updates to parent connection URI domains or the base tenant configuration. In multi-tenant deployments, an attacker possessing a valid API key for one application can exploit this logic flaw to modify the parent domain configuration, potentially impacting sibling applications.

## Impact

Successful exploitation allows unauthorized cross-tenant modifications. Observed impacts include the replacement of API keys, modification of sibling application user data, session hijacking, lockout of legitimate application administrators, and establishment of persistence via unauthorized dashboard user accounts. Additionally, manipulation of the base tenant target allows an attacker to alter authentication factors (firstFactors) and recipe-enabled flags, impacting service availability and login integrity.

## Recommendation

1. Upgrade SuperTokens Core to the fixed versions (6.0.24, 7.0.23, 8.0.7, 9.0.6, 9.1.6, 9.2.7, 9.3.5, 10.0.8, 10.1.9, 11.0.9, 11.1.4, 11.2.4, 11.3.8, 11.4.8, 12.0.11, 12.1.2, 12.2.1, or 12.3.1).
2. Audit current multi-tenant configurations for unauthorized modifications to `api_keys` or authentication factor settings within the SuperTokens Core backend logs.
3. Restrict administrative access to the `multitenancy` API endpoints.
