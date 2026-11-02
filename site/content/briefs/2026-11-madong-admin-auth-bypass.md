---
brief_id: brief-2026-11-02-madong-admin-auth-bypass
event_id: brief-2026-11-02-madong-admin-auth-bypass
revision: 2
activity_at: "2026-11-02T15:52:01Z"
revision_history:
  - revision: 2
    at: "2026-11-02T15:52:01Z"
    checksum: sha256:4faca093ec5cfa19e9d10a662cec4a69c80ef75aa6808a5845c3e7efd36ad415
    summary: added coverage for madong-admin-saas (<= 5.1.4)
    changed_fields:
      - action_plan
      - cves
      - lastmod
      - priority_signals
      - qa_status
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120445
title: 'madong-admin-saas: Missing authentication in tenant management API (CVE-2026-120446)'
slug: 2026-11-madong-admin-auth-bypass
description: A missing authentication vulnerability in madong-admin-saas version 5.1.4 and earlier allows unauthenticated remote attackers to perform full CRUD operations on tenant management and subscription API endpoints.
date: "2026-11-02T15:47:33Z"
lastmod: "2026-11-02T15:50:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:madong:madong-admin-saas:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - api-security
  - cve-2026-120446
  - privilege-escalation
  - access-control
vendors:
  - madong
products:
  - madong-admin-saas (<= 5.1.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can reuse a tenant login JWT against /platformapi controllers to create platform administrator accounts, read tenant database settings, and take control of every tenant.
    confidence_band: high
cves:
  - id: CVE-2026-120446
    cvss: 9.4
    kev_status: "false"
  - id: CVE-2026-120445
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120446
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120445
rules:
  - title: Detect CVE-2026-120446 Exploitation - Unauthorized Access to Tenant API
    description: Detects unauthenticated access attempts to restricted tenant management endpoints in madong-admin-saas
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
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory madong-admin-saas deployments and identify versions <= 5.1.4
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure for CVE-2026-120446
    - action: Patch madong-admin-saas once the vendor releases a version > 5.1.4
      owner: IT Operations
      due: As Available
      evidence: Vulnerability affects versions through 5.1.4
  hunt_leads:
    - lead: Search for unauthorized POST/PUT/DELETE methods against /platformapi/tenant/ endpoints
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source states unauthenticated remote attackers can call account, bind-plan and sync-data endpoints
    - lead: Identify unauthorized access attempts to the /platformapi/ path originating from tenant-assigned JWTs
      technique_id: T1068
      data_needed:
        - Web server access logs or application-level audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can reuse a tenant login JWT against /platformapi controllers
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to /platformapi/ endpoints to trusted management infrastructure
      owner: IT Operations
      addresses: CVE-2026-120446
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-11-02T15:50:56Z"
    level: L2
    summary: added coverage for madong-admin-saas (<= 5.1.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120445
---

CVE-2026-120446 is a critical authentication bypass vulnerability in the 'madong-admin-saas' platform. The flaw originates from a middleware configuration error where the 'platformapi' key fails to validate against the 'platform' application, effectively disabling authentication for specific API endpoints. Unauthenticated attackers can access, modify, or delete tenant accounts and subscription plans by interacting directly with the exposed API.

## Impact

Successful exploitation allows unauthenticated remote attackers to list, create, modify, disable, or delete tenants, and modify subscription plans via the platform tenant management API.

## Recommendation

1. Inventory all instances of 'madong-admin-saas' running version 5.1.4 or earlier.
2. Prioritize upgrading to the latest patched version of the software.
3. If immediate patching is not possible, apply network access control lists (ACLs) to restrict access to the /platformapi/ endpoints to known-trusted management IP ranges.
4. Implement logging for all requests to the /platformapi/tenant/account, bind-plan, and sync-data endpoints to identify unauthorized access attempts.
