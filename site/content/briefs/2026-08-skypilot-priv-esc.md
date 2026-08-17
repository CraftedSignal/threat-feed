---
title: SkyPilot Privilege Escalation Vulnerability (CVE-2026-75481)
slug: 2026-08-skypilot-priv-esc
description: SkyPilot versions through 0.13.1rc1 are vulnerable to a privilege escalation flaw allowing authenticated users to elevate service account roles to administrator, resulting in full platform takeover.
date: "2026-08-17T22:51:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - cloud-security
  - cve-2026-75481
vendors:
  - skypilot-org
products:
  - skypilot
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: SkyPilot fails to validate that authenticated users are entitled to grant administrator roles when updating service account permissions.
    confidence_band: high
cves:
  - id: CVE-2026-75481
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75481
  - https://www.vulncheck.com/advisories/skypilot-authentication-bypass-via-service-account-role-escalation
  - https://github.com/skypilot-org/skypilot/commit/8a3e00259cd374e662cd876c037164bcb070f78e
rules:
  - title: Detect CVE-2026-75481 Exploitation - Unauthorized Service Account Role Change
    description: Detects potential exploitation of CVE-2026-75481 by identifying administrative role update requests to the service account management endpoint.
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch SkyPilot to 0.13.2 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-75481
  hunt_leads:
    - lead: Audit logs for unauthorized service account creations or role updates
      technique_id: T1068
      data_needed:
        - Application audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Description of vulnerability exploitation path
  mitigation_plan:
    - priority: immediate
      action: Upgrade SkyPilot and review service account permissions
      owner: IT Operations
      addresses: CVE-2026-75481
      evidence: NVD Advisory
---

SkyPilot versions through 0.13.1rc1 are affected by a critical privilege management vulnerability, identified as CVE-2026-75481. The flaw resides in the service account management logic, specifically within the `sky/users/server.py` module, where the application fails to perform authorization checks when a user attempts to update the permissions of a service account. 

An authenticated attacker can leverage this oversight to create a new service account and subsequently elevate that account's permissions to the administrator level. By obtaining a bearer token for the newly escalated service account, the attacker can impersonate an administrator to gain full control over all user workspaces and platform configurations. Given the potential for complete administrative compromise of the SkyPilot instance, this vulnerability is rated as High severity.

## Attack Chain

1. Attacker authenticates to the target SkyPilot instance as a standard user.
2. Attacker invokes the service account creation API endpoint to provision a new, low-privileged service account.
3. Attacker identifies the API request responsible for updating service account permissions.
4. Attacker sends a crafted request to the permission update endpoint, targeting the newly created service account.
5. The application backend fails to validate that the requesting user possesses administrative privileges before processing the role elevation request.
6. Attacker confirms the service account role has been elevated to 'administrator' status.
7. Attacker requests a bearer token associated with the elevated service account.
8. Attacker utilizes the administrator-level bearer token to perform unauthorized administrative actions across all workspaces.

## Impact

Successful exploitation of CVE-2026-75481 grants an attacker full administrative control over a SkyPilot environment. This includes the ability to modify, delete, or inspect any user workspace, potentially leading to widespread data exfiltration, service disruption, and unauthorized compute resource consumption. The impact is significant for multi-tenant or team-based environments relying on SkyPilot for workload orchestration.

## Recommendation

1. Upgrade SkyPilot to version 0.13.2 or later immediately to include the patch for CVE-2026-75481.
2. Audit existing service accounts for unauthorized administrative privileges using current platform logs.
3. Revoke any bearer tokens associated with service accounts created or modified within the last 30 days if unauthorized activity is suspected.
4. Monitor web server logs for requests to service account management endpoints originating from non-administrator user accounts.
