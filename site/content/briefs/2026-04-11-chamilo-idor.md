---
brief_id: brief-2026-04-11-chamilo-idor
event_id: brief-2026-04-11-chamilo-idor
revision: 2
activity_at: "2026-04-11T12:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:52689f039ea4e768eedd9af8ab987a36d00a0863b8b41dffa7350cb6a84dee74
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Chamilo LMS IDOR Vulnerability Allows Learning Path Manipulation
slug: 2026-04-11-chamilo-idor
description: Chamilo LMS before versions 1.11.38 and 2.0.0-RC.3 is vulnerable to an Insecure Direct Object Reference (IDOR) vulnerability, allowing authenticated users to modify the learning path progress of other users by manipulating the 'uid' parameter in the lp_ajax_save_item.php endpoint.
date: "2026-04-11T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - chamilo
  - lms
  - idor
  - cve-2026-33702
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33702
    cvss: 7.1
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33702
rules:
  - title: Detect Chamilo LMS Learning Path Manipulation via IDOR
    description: Detects attempts to manipulate Learning Path progress by exploiting the IDOR vulnerability in lp_ajax_save_item.php by monitoring the user ID parameter.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Chamilo LMS - POST Request to lp_ajax_save_item.php
    description: Detects POST request to vulnerable Learning Path endpoint lp_ajax_save_item.php
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, a widely used learning management system, is susceptible to an Insecure Direct Object Reference (IDOR) vulnerability affecting versions prior to 1.11.38 and 2.0.0-RC.3. This flaw resides in the `lp_ajax_save_item.php` endpoint, which handles saving Learning Path progress. The vulnerability allows any authenticated user enrolled in a course to manipulate the learning path progress of other users, including scores, status, completion, and time spent. This is achieved by directly modifying the `uid` parameter in the HTTP request, which specifies the target user ID, without proper authorization checks. Successful exploitation could lead to unauthorized modification of student records and potentially impact grading and certification processes. It is critical to upgrade to the patched versions to mitigate this risk.

## Attack Chain

1. An attacker authenticates to the Chamilo LMS platform with a valid user account.
2. The attacker enrolls in a course containing a Learning Path.
3. The attacker identifies the target user's ID within the course (e.g., from the user list or course roster).
4. The attacker initiates an action that triggers a request to `lp_ajax_save_item.php`.
5. The attacker intercepts the HTTP request (e.g., using browser developer tools or a proxy).
6. The attacker modifies the `uid` parameter in the request to the target user's ID.
7. The attacker modifies other parameters related to learning path progress such as score, status, completion, or time.
8. The attacker submits the modified request to `lp_ajax_save_item.php`, resulting in the target user's learning path progress being altered.

## Impact

Successful exploitation of this IDOR vulnerability allows an attacker to arbitrarily modify the learning path progress of other users within Chamilo LMS. This could lead to students receiving credit for work they did not complete or having their progress unfairly reset. This could affect the integrity of the course grading system and lead to inaccurate certifications or diplomas being awarded. This can undermine trust in the educational institution and the value of its credentials.

## Recommendation

*   Upgrade Chamilo LMS to version 1.11.38 or 2.0.0-RC.3 to patch CVE-2026-33702.
*   Deploy the Sigma rule to monitor for suspicious requests to `lp_ajax_save_item.php` with modified `uid` parameters.
*   Implement stricter access controls and input validation for user ID parameters in all API endpoints.
