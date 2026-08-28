---
title: Improper Access Control in HyperDX Team Management
slug: 2026-08-hyperdx-auth-bypass
description: HyperDX versions through 1.10.1 contain an improper access control vulnerability allowing authenticated users to perform unauthorized administrative actions via team management API endpoints.
date: "2026-08-28T21:38:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hyperdx:hyperdx:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-application-security
vendors:
  - HyperDX
products:
  - HyperDX (<= 1.10.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: HyperDX through 1.10.1 fails to enforce role-based access controls in team management endpoints, allowing any team member to perform administrative actions.
    confidence_band: high
cves:
  - id: CVE-2026-82279
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82279
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade HyperDX to a version greater than 1.10.1
      owner: IT Operations
      due: 72h
      evidence: HyperDX through 1.10.1 fails to enforce role-based access controls
  hunt_leads:
    - lead: Identify anomalous API calls to /team/ endpoints from non-admin user accounts
      technique_id: T1068
      data_needed:
        - Web server access logs or API gateway logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can delete team members... by sending requests to PATCH /team/apiKey, PATCH /team/name, and DELETE /team/member
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest version
      owner: IT Operations
      addresses: CVE-2026-82279
      evidence: NVD advisory for CVE-2026-82279
---

HyperDX versions through 1.10.1 contain a critical authorization flaw within their team management API endpoints. Due to a failure to properly enforce role-based access controls (RBAC), any authenticated team member can bypass existing permission tiers to execute administrative functions. An attacker with standard user access can manipulate team settings, including renaming the team, rotating API keys, and removing other users, including the team owner. This vulnerability presents a significant risk to organizational account security and sensitive data access if administrative tokens are compromised. Defenders should identify HyperDX instances and verify the software version against the patched release.

## Impact

Successful exploitation allows unauthorized users to modify team configurations and gain administrative control over the platform. This may lead to service disruption, account lockout for authorized administrators, or potential exfiltration of sensitive telemetry data via rotated API keys.

## Recommendation

* Patch HyperDX instances by upgrading to the latest version that addresses CVE-2026-82279.
* Audit logs for suspicious activity involving PATCH or DELETE requests directed at /team/ endpoints, specifically monitoring for non-admin accounts performing team management functions.
