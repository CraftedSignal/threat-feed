---
title: WWBN AVideo Privilege Escalation via Moderator Account
slug: 2024-01-22-avideo-privilege-escalation
description: WWBN AVideo platform versions up to 26.0 allows a 'Videos Moderator' to escalate privileges and perform unauthorized video management operations due to inconsistent authorization checks.
date: "2026-03-23T19:16:41Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - avideo
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33650
rules:
  - title: AVideo Unauthorized Video Deletion Attempt
    description: Detects attempts to delete videos via videoDelete.json.php by users with Videos Moderator role after an ownership change, indicating potential privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: AVideo Suspicious Video Ownership Transfer
    description: Detects attempts to change video ownership via videoAddNew.json.php by users with Videos Moderator role, potentially leading to unauthorized deletion.
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

WWBN AVideo, an open-source video platform, is vulnerable to a privilege escalation flaw. Specifically, AVideo versions up to and including 26.0, a user with "Videos Moderator" permissions can perform unauthorized video management operations. The vulnerability stems from the inconsistent authorization checks within the platform's code. While the "Videos Moderator" permission is intended to only permit changes to video publicity (Active, Inactive, Unlisted), the flaw allows for full video editing operations, including ownership transfer and video deletion. This vulnerability was patched in commit 838e16818c793779406ecbf34ebaeba9830e33f8. Successful exploitation of this flaw could lead to data loss and unauthorized content manipulation.

## Attack Chain

1. An attacker gains access to a legitimate "Videos Moderator" account on the AVideo platform.
2. The attacker leverages the `Permissions::canModerateVideos()` function within `videoAddNew.json.php` to initiate video editing operations beyond the intended scope of the moderator role.
3. The attacker modifies the ownership of a target video, transferring it to an account controlled by the attacker.
4. The attacker, now the owner of the target video, bypasses the intended authorization controls within the `videoDelete.json.php` script.
5. The attacker invokes the `videoDelete.json.php` script to delete the video.
6. The platform deletes the video, due to the successful ownership transfer and the insufficient permission checks in the delete function.
7. The attacker repeats the process to delete any video on the platform.

## Impact

Successful exploitation of this vulnerability allows an attacker with limited "Videos Moderator" privileges to escalate their access and perform unauthorized video management operations. This can lead to the deletion of arbitrary videos on the platform, resulting in data loss, service disruption, and potential reputational damage. The number of affected installations is unknown.

## Recommendation

*   Apply the patch from commit 838e16818c793779406ecbf34ebaeba9830e33f8 to address the vulnerability in AVideo (CVE-2026-33650).
*   Monitor web server logs for requests to `videoAddNew.json.php` and `videoDelete.json.php` originating from "Videos Moderator" accounts, looking for anomalous activity (see Sigma rule below).
*   Implement stricter authorization controls for video management operations within the AVideo platform to prevent privilege escalation.
