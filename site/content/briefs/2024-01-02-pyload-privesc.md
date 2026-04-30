---
title: pyLoad Privilege Escalation Vulnerability (CVE-2026-41133)
slug: 2024-01-02-pyload-privesc
description: pyLoad versions up to 0.5.0b3.dev97 cache user roles and permissions in the session, leading to privilege escalation even after an admin revokes privileges.
date: "2026-04-22T00:16:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - pyLoad
  - privilege-escalation
  - CVE-2026-41133
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41133
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41133
rules:
  - title: Detect pyLoad Admin Role Change Followed by User Activity
    description: Detects a user performing actions after their role has been changed by an administrator, potentially indicating exploitation of CVE-2026-41133.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-41133
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect PyLoad Unauthorized API Access
    description: Detects access to sensitive API endpoints after a role change, indicating potential privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-41133
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

pyLoad, a free and open-source download manager written in Python, is vulnerable to a privilege escalation issue. Specifically, versions up to and including 0.5.0b3.dev97 cache user `role` and `permission` data within the session upon login. This cached data is then used to authorize subsequent requests, even if an administrator modifies the user's roles or permissions directly in the database. Consequently, a user who is already logged in retains their original, possibly revoked, privileges until they log out or their session expires. This vulnerability, identified as CVE-2026-41133, stems from a core authorization/session-consistency flaw within pyLoad and allows for potentially unauthorized actions to be performed. The fix for this vulnerability is included in commit e95804fb0d06cbb07d2ba380fc494d9ff89b68c1.

## Attack Chain

1. An attacker gains initial access to a pyLoad user account, either through credential compromise or other means.
2. The attacker logs into pyLoad, establishing a session. The user's roles and permissions are cached within this session.
3. A pyLoad administrator revokes specific privileges or changes the role associated with the attacker's account in the pyLoad database.
4. The attacker, still logged in with the existing session, attempts to perform an action that should now be unauthorized given the administrator's changes.
5. pyLoad authorizes the action based on the cached roles and permissions stored in the session, effectively bypassing the updated authorization settings.
6. The attacker successfully completes the privileged action. This could involve accessing sensitive data, modifying system settings, or initiating unauthorized downloads.
7. The attacker continues to exploit the stale session data to perform further unauthorized actions, maintaining escalated privileges until session expiry or logout.

## Impact

Successful exploitation of CVE-2026-41133 can lead to significant privilege escalation within pyLoad. An attacker with a compromised account can retain administrative-level access even after their permissions have been revoked. The scope of the impact depends on the specific privileges granted to the compromised user and the actions they are able to perform within pyLoad. This could potentially lead to unauthorized access to downloaded files, modification of download settings, or disruption of the download manager's functionality.

## Recommendation

*   Apply the patch provided in commit e95804fb0d06cbb07d2ba380fc494d9ff89b68c1 to address the vulnerability.
*   Monitor pyLoad logs for any suspicious activity following user permission changes, particularly attempts to access restricted functions, to detect potential exploitation attempts related to CVE-2026-41133.
*   Implement stricter session management policies, such as shorter session timeouts, to minimize the window of opportunity for attackers to exploit this vulnerability.
*   Deploy the Sigma rule `DetectPyLoadPrivilegeEscalation` to identify potential exploit attempts.
