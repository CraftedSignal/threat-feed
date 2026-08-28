---
title: Incus Custom Volume Authorization Bypass
slug: 2026-08-incus-bypass
description: A vulnerability in Incus allows unauthorized users to bypass project restrictions and copy custom storage volumes by exploiting missing authorization checks in the creation handler.
date: "2026-08-28T21:15:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lxc:incus:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - cve-2026-55621
vendors:
  - LXC
products:
  - Incus (v7 < 7.2.0)
  - Incus (v6 <= 6.23.0)
  - Incus (<= 0.7.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This issue could allow an attacker to access secrets in custom volumes they are not authorized to access.
    confidence_band: high
cves:
  - id: CVE-2026-55621
    cvss: 7.7
    epss: 0.00201
references:
  - https://github.com/advisories/GHSA-64f3-v33m-w89f
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Incus to version 7.2.0 or current patched version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-55621 mitigation
  hunt_leads:
    - lead: Audit API logs for POST requests to /1.0/storage-pools/*/volumes/custom where the requester has limited access to the source project
      technique_id: T1068
      data_needed:
        - Incus API logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Authorization bypass exploitation technique
  mitigation_plan:
    - priority: immediate
      action: Rotate certificates for users identified in access logs targeting sensitive projects
      owner: Security Operations
      addresses: CVE-2026-55621
      evidence: Risk of unauthorized data access
---

The Incus storage volume creation handler is susceptible to an authorization bypass vulnerability identified as CVE-2026-55621. This flaw allows an authenticated but restricted user to copy custom storage volumes from projects they are not authorized to access into a project under their control. The issue arises because the system verifies authorization for the target project but fails to perform an entitlement check, such as a 'CanView' verification, on the source volume or project before passing the user-controlled source parameter to the copy function. An attacker only requires knowledge of the target project name and the specific custom volume name to trigger the unauthorized copy. While the operation is restricted to the local server, the resulting copy can subsequently be moved to external infrastructure. This vulnerability impacts Incus versions v7 prior to 7.2.0, v6 through 6.23.0, and baseline versions up to 0.7.0.

## Attack Chain

1. Attacker authenticates to the Incus API using an existing user certificate with restricted project access.
2. Attacker identifies the name of a target project and a sensitive custom volume residing within that project.
3. Attacker initiates an HTTP POST request to the `/1.0/storage-pools/{pool}/volumes/custom` endpoint.
4. The request payload includes the attacker-controlled `source.project` and `source.name` fields.
5. The Incus storage volume creation handler validates the authorization for the destination project.
6. The handler fails to perform an entitlement or `CanView` check on the source project and volume.
7. The system creates a copy of the unauthorized custom volume in the attacker-controlled project.
8. Attacker accesses the copied volume to exfiltrate sensitive data or credentials.

## Impact

Successful exploitation allows unauthorized access to sensitive data stored in custom volumes. If the volume contains system secrets, database files, or configuration data, the attacker can leverage this information for further lateral movement or privilege escalation within the environment.

## Recommendation

Prioritize the upgrade of all Incus instances to the patched versions as indicated by the vendor. For v7, upgrade to 7.2.0 or later; for v6, move to a patched release beyond 6.23.0. In the interim, restrict access to the Incus API to known, trusted certificates and perform regular audits of storage volume access logs to identify attempts to copy volumes across projects.
