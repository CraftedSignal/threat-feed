---
brief_id: brief-2026-11-03-smart-sso-auth
event_id: brief-2026-11-03-smart-sso-auth
revision: 2
activity_at: "2026-11-03T21:28:45Z"
revision_history:
  - revision: 2
    at: "2026-11-03T21:28:45Z"
    checksum: sha256:f3f295767cc03d4b5ec67f962579254e7ef4388e1efb70e2c5e2c19f814c6d0c
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-121543&utm_source=rss&utm_medium=rss
title: 'smart-sso: Incorrect authorization in PermissionFilter (CVE-2026-121543)'
slug: 2026-11-smart-sso-auth
description: An incorrect authorization vulnerability in smart-sso versions 2.0.1 and earlier allows authenticated users to access administrative APIs due to a permissive default configuration in PermissionFilter.
date: "2026-11-03T18:01:06Z"
lastmod: "2026-11-03T21:27:54Z"
type: advisory
claim_state: <nil>
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
  - cpe:2.3:a:smart-sso:smart-sso:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-121543&utm_source=rss&utm_medium=rss
tags:
  - privilege-escalation
  - authentication-bypass
  - web-application
vendors:
  - smart-sso
products:
  - smart-sso (<= 2.0.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can call /admin/user-role/save to assign themselves the administrator role
    confidence_band: high
cves:
  - id: CVE-2026-121543
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121543
  - https://sploitus.com/exploit?id=CVE-2026-121543&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Potential Unauthorized Access to smart-sso Admin APIs
    description: Detects unauthorized access attempts to smart-sso administrative API endpoints by monitoring requests to the /admin/ path hierarchy
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify and patch all instances of smart-sso versions 2.0.1 and earlier
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-121543 vulnerability disclosure
  hunt_leads:
    - lead: Investigate access logs for requests to /admin/ paths originating from non-administrative service accounts or user sessions
      technique_id: T1068
      data_needed:
        - Web access logs (cs-uri-stem, cs-username)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows authenticated users to call admin console APIs
  mitigation_plan:
    - priority: immediate
      action: Implement Web Application Firewall (WAF) rules to block /admin/* paths from non-administrative segments
      owner: SOC
      addresses: CVE-2026-121543
      evidence: Incorrect authorization in PermissionFilter
updates:
  - at: "2026-11-03T21:27:54Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-121543&utm_source=rss&utm_medium=rss
---

The PermissionFilter component in smart-sso up to version 2.0.1 fails to properly restrict access to administrative console APIs. Because the filter permits unlisted paths by default, any authenticated user can invoke sensitive administrative functions. An attacker can exploit this to perform actions such as calling '/admin/user-role/save' to assign themselves administrative privileges, reset passwords, or manage applications across integrated systems.

## Impact
Exploitation allows an authenticated user to achieve full administrative control over the smart-sso environment. This includes the ability to modify user roles, perform password resets, and gain management access to integrated systems linked to the SSO platform.

## Recommendation
- Update smart-sso to a version beyond 2.0.1 that addresses the permissive authorization logic in PermissionFilter.
- Audit access logs for unauthorized requests to the '/admin/' path hierarchy made by non-administrative user accounts.
- Configure the web server or application firewall to explicitly deny access to administrative API endpoints for all users except those assigned to the administrator role.
