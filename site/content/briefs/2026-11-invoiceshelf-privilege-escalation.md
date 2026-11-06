---
brief_id: brief-2026-11-06-invoiceshelf-privilege-escalation
event_id: brief-2026-11-06-invoiceshelf-privilege-escalation
revision: 1
activity_at: "2026-11-06T02:20:35Z"
title: 'InvoiceShelf: Cross-tenant privilege escalation (CVE-2026-122158)'
slug: 2026-11-invoiceshelf-privilege-escalation
description: InvoiceShelf versions 2.4.3 and 3.0.0-alpha.3 are vulnerable to cross-tenant privilege escalation allowing an authenticated tenant owner to gain administrative control over other tenants on the same installation.
date: "2026-11-06T02:20:35Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:invoiceshelf:invoiceshelf:*:*:*:*:*:*:*:*
tags:
  - web-application
  - privilege-escalation
  - authentication-bypass
vendors:
  - InvoiceShelf
products:
  - InvoiceShelf (2.4.3, 3.0.0-alpha.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: InvoiceShelf cross-tenant privilege escalation allows owners to assign arbitrary roles.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The controller verifies that the caller owns the active company. It does not bind that authorization decision to companies[].id in the request body.
    confidence_band: high
cves:
  - id: CVE-2026-122158
    cvss: 4.7
    epss: 0.00272
    kev_status: "false"
references:
  - https://github.com/InvoiceShelf/InvoiceShelf/security/advisories/GHSA-c9cx-7r7m-264v
  - https://vulners.com/cve/CVE-2026-122158
  - https://vuldb.com/vuln/431158
  - https://github.com/InvoiceShelf/InvoiceShelf/pull/826
  - https://github.com/InvoiceShelf/InvoiceShelf/pull/822
  - https://sploitus.com/exploit?id=762B914A-533E-595C-BBA6-21D6374ED0D7&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade InvoiceShelf to version 2.4.4 or 3.0.0-alpha.4.
      owner: IT Operations
      due: 48h
      evidence: Remediation provided in vendor security advisory.
  hunt_leads:
    - lead: Identify API requests to /api/v1/members where the requested Company ID does not match the active session context.
      technique_id: T1068
      data_needed:
        - Web server access logs or application audit logs containing request bodies
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The controller verifies that the caller owns the active company. It does not bind that authorization decision to companies[].id in the request body.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2.4.4 or 3.0.0-alpha.4.
      owner: IT Operations
      addresses: CVE-2026-122158
      evidence: 'Patch for the 2.x line, PR #826 and Patch for the 3.x line, PR #822.'
---

InvoiceShelf contains a cross-tenant privilege escalation vulnerability (CVE-2026-122158) stemming from improper authorization checks during member creation and update operations. The application fails to validate that a company owner is authorized to manage memberships for companies other than their own, allowing an attacker to assign themselves or another account an arbitrary role (including 'owner') within a target tenant.

## Attack Chain
1. Attacker authenticates to InvoiceShelf as an owner of a legitimate tenant (Company A).
2. Attacker initiates a `POST` or `PATCH` request to the member management API (`/api/v1/members`).
3. Attacker includes a `companies` array in the request body containing the ID of a target victim tenant (Company B) and an elevated role assignment (e.g., `owner`).
4. The application service layer processes the request.
5. The `MemberService::create()` or `update()` methods receive the malicious payload.
6. The application performs a Bouncer authorization scope switch to the victim tenant ID without validating that the attacker is an owner of that specific company.
7. The application synchronizes the attacker's account role with the victim company, granting the requested privilege.

## Impact
Successful exploitation allows an authenticated user to bypass tenant isolation, granting unauthorized access to financial records, customer data, and administrative settings of other tenants on the same installation.

## Recommendation
- Upgrade InvoiceShelf to version 2.4.4 or 3.0.0-alpha.4 or later immediately.
- Review system logs for unexpected membership changes or administrative role assignments occurring via API requests, specifically looking for `POST` or `PATCH` requests to `/api/v1/members` containing cross-company IDs.
- Audit existing tenant memberships for anomalous 'owner' roles assigned to accounts that should not have cross-tenant access.
