---
title: WWBN AVideo Privilege Escalation via Moderator Account
slug: 2024-01-22-avideo-privilege-escalation
description: WWBN AVideo platform versions up to 26.0 allows a 'Videos Moderator' to escalate privileges and perform unauthorized video management operations due to inconsistent authorization checks.
date: "2026-03-23T19:16:41Z"
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

WWBN AVideo, an open-source video platform, is vulnerable to a privilege escalation flaw. Specifically, AVideo versions up to and including 26.0, a user with "Videos Moderator" permissions can perform unauthorized video management operations. The vulnerability stems from the inconsistent authorization checks within the platform's code. While the "Videos Moderator" permission is intended to only permit changes to video publicity (Active, Inactive, Unlisted), the flaw allows for full video…
