---
title: Authorization Bypass in APIPark
slug: 2026-10-apipark-auth-bypass
description: APIPark versions through 1.9.7-beta are vulnerable to an authorization bypass allowing authenticated team managers to manipulate team IDs to access, modify, or delete resources belonging to other teams.
date: "2026-10-16T18:49:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apipark:apipark:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - authorization-bypass
  - api-security
vendors:
  - APIPark
products:
  - APIPark (<= 1.9.7-beta)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: APIPark through 1.9.7-beta contains an authorization bypass vulnerability that allows authenticated team managers to access other teams' services and applications.
    confidence_band: high
cves:
  - id: CVE-2026-111680
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111680
rules:
  - title: Detect CVE-2026-111680 Exploitation Attempt - Unauthorized Team Resource Access
    description: Detects potential CVE-2026-111680 exploitation by monitoring for requests to sensitive API endpoints where the team query parameter is manipulated.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade APIPark to a patched version beyond 1.9.7-beta
      owner: IT Operations
      due: 48h
      evidence: Source identifies vulnerability in versions through 1.9.7-beta
  hunt_leads:
    - lead: Search logs for unusual team ID patterns or cross-team access attempts to sensitive API endpoints
      technique_id: T1068
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can target service or app ids exposed by /api/v1/simple/services and /api/v1/simple/apps
  mitigation_plan:
    - priority: immediate
      action: Upgrade APIPark
      owner: IT Operations
      addresses: CVE-2026-111680
      evidence: NVD vulnerability disclosure
---

APIPark through version 1.9.7-beta is susceptible to an authorization bypass vulnerability (CVE-2026-111680) that impacts multi-tenant environments. The flaw allows an authenticated user with the 'team manager' role to manipulate the 'team' query parameter in API requests. By substituting their own team ID with that of a target team, an attacker can bypass authorization controls and interact with resources they do not own.

This vulnerability grants attackers the ability to read, modify, or delete services and applications belonging to other teams. The attack is carried out by discovering target service or application IDs through information-gathering endpoints, followed by unauthorized requests to management endpoints. The impact is significant for organizations relying on APIPark for API gateway management, as it undermines the logical separation between teams, potentially leading to unauthorized data exposure or operational disruption of sensitive API services.

## Impact

Successful exploitation allows unauthorized users to perform administrative actions on services and applications across different teams. This can result in the loss of service availability, unauthorized modification of API configurations, or the exfiltration of metadata and sensitive details related to internal services. This vulnerability is critical in environments with high internal traffic or multiple distinct development/production teams sharing an APIPark instance.

## Recommendation

Prioritized actions for security teams to address CVE-2026-111680:

- Upgrade APIPark to the latest version immediately to remediate the authorization logic flaw identified in CVE-2026-111680.
- Review web server and API gateway access logs for abnormal patterns involving requests to /api/v1/service/info or /api/v1/app where the 'team' parameter does not match the requester's legitimate assigned ID.
- Audit existing team manager permissions and minimize administrative access until the patch is applied.
