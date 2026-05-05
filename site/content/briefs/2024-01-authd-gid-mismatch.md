---
title: authd Incorrect Primary Group ID Vulnerability
slug: 2024-01-authd-gid-mismatch
description: authd 0.6.0 contains a bug that leads to an incorrect primary group ID being set to the user's UID, potentially leading to local privilege escalation and incorrect file ownership, fixed in authd >= 0.6.4.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - linux
  - authd
vendors:
  - Canonical
products:
  - authd
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6970
    epss: 0.00015
references:
  - https://github.com/advisories/GHSA-fg3j-5w9g-hmg7
  - https://github.com/canonical/authd/issues/1482
  - https://github.com/canonical/authd/commit/154b428305cb1a7a19c897626fefd09d6dde8b9f
rules:
  - title: Detect authctl Group Set-GID Execution
    description: Detects the execution of authctl group set-gid command, which can be used to exploit CVE-2026-6970 if abused.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
  - title: Detect GID Modification via authctl
    description: Detects attempts to modify a user's GID using authctl, which could be indicative of an attempt to exploit CVE-2026-6970
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

authd version 0.6.0 contains a vulnerability related to how it sets the primary group ID (GID) for users. Specifically, when a user's GID differs from their UID (either due to initial creation with authd < 0.5.4 or manual modification via `authctl group set-gid`), authd can incorrectly set the primary group ID to the user's UID upon login if some user information changed in the identity provider. This occurs because the user record is updated upon login. This issue affects users whose primary group ID differs from their UID. The vulnerability, identified as CVE-2026-6970, can lead to local privilege escalation, as well as creating files and directories with incorrect group ownership, potentially granting unintended access to other local users. The vulnerability has been fixed in authd versions >= 0.6.4.

## Attack Chain

1. User is created with authd < 0.5.4, resulting in a UID != GID, or an existing user's primary group is manually modified using `authctl group set-gid`.
2. User information is changed in the identity provider, triggering a user record update upon login.
3. The affected user logs in.
4. authd incorrectly sets the user's primary group ID to their UID instead of the correct GID.
5. User attempts to create a new file or directory.
6. The newly created file or directory is assigned the incorrect group ownership (UID instead of GID).
7. Another local user, who is a member of the correct GID, attempts to access the file.
8. The second local user may gain unintended access to the file due to the incorrect group ownership, potentially leading to unauthorized information disclosure or modification.

## Impact

This vulnerability can result in local privilege escalation if users gain access to files or directories they should not have access to. It can also lead to data breaches if sensitive information is exposed due to incorrect file permissions. The number of affected users depends on the deployment of authd and the number of users whose primary group ID differs from their UID. If exploited, the impact could range from unauthorized access to sensitive data to complete system compromise depending on the permissions granted to the incorrectly owned files.

## Recommendation

*   Upgrade authd to version 0.6.4 or later to remediate CVE-2026-6970.
*   Use the provided script from the advisory to correct the primary group ID of all authd users and update file ownership in the home directory, referencing the script provided in the Overview.
*   After applying the fix, force affected users to log out and log back in using `sudo loginctl terminate-user "$user"` to ensure the changes are reflected, referencing the command in the Overview.
*   Monitor authd logs for instances of `authctl group set-gid` being executed by unauthorized users.
