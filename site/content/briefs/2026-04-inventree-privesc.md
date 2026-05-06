---
title: InvenTree Privilege Escalation via API Abuse (CVE-2026-35476)
slug: 2026-04-inventree-privesc
description: A non-staff authenticated user can elevate their account to a staff level via a POST request against their user account endpoint in InvenTree versions prior to 1.2.7 and 1.3.0 due to improperly configured API write permissions.
date: "2026-04-08T20:16:24Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - inventree
  - privilege-escalation
  - cve-2026-35476
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35476
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35476
  - https://github.com/inventree/InvenTree/security/advisories/GHSA-r8q5-3595-3jh2
  - https://docs.inventree.org/en/stable/concepts/threat_model/#assumed-trust
rules:
  - title: InvenTree User Staff Status Modification via API
    description: Detects POST requests to the InvenTree API that attempt to modify a user's staff status.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: InvenTree Suspicious API POST Request
    description: Detects POST requests with is_staff=true to the InvenTree API server to identify potential exploit attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-35476 is a privilege escalation vulnerability affecting InvenTree, an open-source inventory management system. The vulnerability resides in versions prior to 1.2.7 and 1.3.0. It allows a non-staff authenticated user to elevate their account privileges to a staff level. This is achieved by sending a specially crafted POST request to the user's account endpoint. The root cause is due to improperly configured write permissions on the API endpoint, enabling unauthorized modification of the user's staff status. Upgrading to versions 1.2.7 or 1.3.0 resolves this issue. This vulnerability allows attackers to gain elevated privileges within the InvenTree system, potentially leading to unauthorized data access, modification, or other malicious activities.

## Attack Chain

1. An attacker registers a standard user account on the InvenTree platform.
2. The attacker authenticates to obtain a valid session token or API key.
3. The attacker crafts a POST request to the user account endpoint, typically `/api/user/<user_id>/`.
4. The POST request includes a data payload modifying the `is_staff` field to `true`.
5. The attacker sends the malicious POST request to the InvenTree server.
6. Due to the improperly configured write permissions, the server accepts the request and updates the user's `is_staff` status in the database.
7. The attacker's account is now elevated to staff level, granting access to administrative functions and data.

## Impact

Successful exploitation of CVE-2026-35476 allows an attacker to escalate their privileges from a standard user to a staff user within the InvenTree system. This can lead to unauthorized access to sensitive inventory data, modification of system settings, creation of new administrator accounts, and potentially full control over the InvenTree instance. The number of affected systems depends on the adoption rate of vulnerable InvenTree versions.

## Recommendation

*   Upgrade InvenTree installations to version 1.2.7 or 1.3.0 or later to patch CVE-2026-35476.
*   Deploy the Sigma rule `InvenTree User Staff Status Modification via API` to detect suspicious POST requests attempting to modify user staff status on the API endpoint.
*   Monitor InvenTree web server logs for POST requests to `/api/user/` endpoints with the `is_staff` parameter, and investigate any unexpected activity.
*   Review InvenTree's threat model and assumed trust configuration documentation (https://docs.inventree.org/en/stable/concepts/threat_model/#assumed-trust) to understand potential risks and hardening measures.
