---
title: CVE-2026-56246 - Capgo Broken Access Control in Organization Management API
slug: 2026-07-capgo-broken-access-control
description: Capgo versions prior to 12.128.2 contain a broken access control vulnerability (CVE-2026-56246) in their organization management API where a scoped API key inherits the full permissions of its owner-user, allowing an attacker to perform destructive operations against unauthorized organizations, bypassing intended scope and leading to privilege escalation and impact.
date: "2026-07-08T14:21:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - data-destruction
  - impact
  - cloud
vendors:
  - Capgo
products:
  - Capgo < 12.128.2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a scoped API key (limited_to_orgs) inherits its owner-user's permissions, allowing destructive cross-organization actions...evaluates the key owner's user privileges before enforcing the API key's limited_to_orgs scope.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Data Destruction
    evidence: can still perform destructive operations (e.g., DELETE /organization...
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: can still perform destructive operations (e.g., ...DELETE /organization/members)
    confidence_band: high
cves:
  - id: CVE-2026-56246
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56246
---

A critical broken access control vulnerability (CVE-2026-56246) has been identified in Capgo versions prior to 12.128.2. This flaw exists within the organization management API, specifically concerning how scoped API keys (configured with `limited_to_orgs`) handle permissions. An attacker who gains access to an API key owned by a user who is an administrator in multiple organizations can leverage this vulnerability. The key, despite being explicitly restricted to a single organization, improperly inherits the full administrative privileges of its owner across all organizations where the owner is an admin. This bypasses the intended scope of the API key, enabling the attacker to perform unauthorized and destructive cross-organization actions, such as deleting entire organizations or removing members using endpoints like `DELETE /organization` and `DELETE /organization/members`. The root cause lies in the application's `rbac_check_permission_direct` logic, which evaluates the owner's global user privileges before enforcing the `limited_to_orgs` restriction. This allows for privilege escalation and significant unauthorized impact.

## Attack Chain

1. An attacker obtains a Capgo API key belonging to a user who holds administrative privileges across multiple Capgo organizations.
2. The attacker configures or identifies an API key intended to have its operations explicitly restricted to a single, designated organization using the `limited_to_orgs` scope.
3. The attacker crafts an API request to perform a destructive action, such as `DELETE /organization` or `DELETE /organization/members`, targeting a *different* organization for which the API key is *not* explicitly authorized.
4. The Capgo application processes the API request, initiating an authorization check that includes a call to `rbac_check_permission_direct`.
5. During this authorization process, the system incorrectly evaluates the full administrative permissions of the API key's owner-user across all their assigned organizations.
6. The system fails to enforce the `limited_to_orgs` scope, neglecting the explicit restriction defined for the API key itself due to the flawed `rbac_check_permission_direct` logic.
7. The destructive API call (e.g., unauthorized organization deletion, member removal) is successfully executed against the unintended target organization, leading to unauthorized data destruction or disruption.

## Impact

The successful exploitation of CVE-2026-56246 can lead to severe consequences, including unauthorized data destruction, service disruption, and privilege escalation. An attacker can leverage an improperly scoped API key to delete entire Capgo organizations or remove critical members from them, even if the key was explicitly meant for a different scope. This can cause significant operational downtime, loss of data, and potentially compromise the integrity of multiple organizational structures within Capgo, affecting all users and data associated with the targeted organizations. The broad impact stems from the ability to affect multiple, supposedly isolated, organizations via a single compromised key.

## Recommendation

* Patch Capgo instances immediately to version 12.128.2 or later to address CVE-2026-56246.
* Review and re-evaluate all existing Capgo API keys, especially those with `limited_to_orgs` scope, to ensure they adhere to the principle of least privilege and their permissions are correctly enforced post-patch.
* Implement strict logging and monitoring for Capgo API key usage, specifically for destructive operations like `DELETE /organization` or `DELETE /organization/members`, to detect anomalous activity related to CVE-2026-56246.
