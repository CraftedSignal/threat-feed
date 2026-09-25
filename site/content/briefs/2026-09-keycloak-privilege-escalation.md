---
title: Keycloak Privilege Escalation Vulnerability
slug: 2026-09-keycloak-privilege-escalation
description: A vulnerability in Keycloak allows a remote, authenticated attacker to perform a privilege escalation to gain administrator access.
date: "2026-09-25T13:59:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - identity-and-access-management
  - privilege-escalation
  - security-advisory
vendors:
  - Red Hat
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in Keycloak ausnutzen, um Administratorrechte zu erlangen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3577
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity Management Team
  immediate_actions:
    - action: Review administrative access logs in Keycloak for suspicious privilege changes.
      owner: Identity Management Team
      due: 24h
      evidence: Source states vulnerability allows administrator privilege escalation.
  mitigation_plan:
    - priority: immediate
      action: Restrict administrative interface access to known, authorized networks.
      owner: IT Operations
      addresses: Keycloak exposure
      evidence: Mitigates impact of unauthorized administrator access.
---

The BSI has released an advisory concerning a vulnerability in Keycloak that enables a remote, authenticated attacker to escalate their privileges and gain administrator-level access. The flaw impacts identity and access management environments where the application is deployed. Because the vulnerability allows for unauthorized administrative control, it poses a significant risk to the integrity and security of the authentication provider. At the time of reporting, no patch has been provided. Defenders should assess their current deployment of Keycloak and implement restrictive access controls to minimize the risk of unauthorized account escalation until an official security update is available from Red Hat.

## Impact

Successful exploitation allows an authenticated user to gain full administrative privileges within the Keycloak instance. This compromise impacts the security of all integrated services that rely on Keycloak for identity management, potentially leading to unauthorized access to downstream applications, exfiltration of user credentials, or full takeover of the identity provider environment.

## Recommendation

1. Monitor Keycloak administrative logs for unauthorized elevation of privilege attempts or unexpected user role assignments.
2. Implement strict least-privilege access for all authenticated users to reduce the number of potential entry points for escalation.
3. Closely monitor Red Hat security advisories for the release of an official patch addressing this vulnerability.
