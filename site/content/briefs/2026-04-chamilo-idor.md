---
title: Chamilo LMS Insecure Direct Object Reference Vulnerability (CVE-2026-32930)
slug: 2026-04-chamilo-idor
description: An Insecure Direct Object Reference (IDOR) vulnerability in Chamilo LMS (CVE-2026-32930) allows authenticated teachers to modify gradebook evaluation settings of other courses by manipulating the 'editeval' GET parameter, leading to unauthorized data modification.
date: "2026-04-10T18:16:42Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - idor
  - chamilo
  - lms
  - cve-2026-32930
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1113
    technique_name: 'Man-in-the-Middle: Interception of legitimate credentials'
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: 'Man-in-the-Middle: Interception of legitimate credentials'
cves:
  - id: CVE-2026-32930
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32930
  - https://github.com/chamilo/chamilo-lms/commit/63e1e6d3d717bd537c7c61719416da35aaa658dd
  - https://github.com/chamilo/chamilo-lms/commit/f03f681df939db0429edc8414fb3ce4e4b80d79d
  - https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-9h22-wrg7-82q6
rules:
  - title: Detect Chamilo Gradebook Edit Request
    description: Detects attempts to modify gradebook evaluations in Chamilo LMS, potentially indicating an IDOR vulnerability exploitation (CVE-2026-32930).
    platform: sigma
    severity: medium
    tactics:
      - collection
      - privilege_escalation
    techniques:
      - T1113
    data_sources:
      - webserver
      - linux
  - title: Detect Chamilo Suspicious POST to Edit Evaluation
    description: Detects POST requests to the edit_evaluation.php endpoint in Chamilo LMS, which could indicate attempts to modify evaluation settings.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1113
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3 are vulnerable to an Insecure Direct Object Reference (IDOR) vulnerability, identified as CVE-2026-32930. This flaw exists in the gradebook evaluation edit page. An authenticated teacher can exploit this vulnerability to view and modify the settings (name, max score, weight) of evaluations belonging to other courses. This is achieved by manipulating the `editeval` GET parameter. Successful exploitation allows unauthorized modification of gradebook settings, potentially affecting student grades and overall course integrity. The vulnerability was patched in versions 1.11.38 and 2.0.0-RC.3. This affects any Chamilo LMS instance running a vulnerable version accessible to authenticated users.

## Attack Chain

1. An attacker authenticates to Chamilo LMS as a teacher.
2. The attacker navigates to the gradebook section of a course they have access to.
3. The attacker identifies the URL used to edit an evaluation, noting the `editeval` parameter and its associated value.
4. The attacker modifies the `editeval` parameter value to reference an evaluation ID from a different course.
5. The attacker submits the modified request to the Chamilo LMS server.
6. The server, due to the IDOR vulnerability, processes the request without proper authorization checks.
7. The attacker is able to view and modify the settings (name, max score, weight) of the evaluation belonging to the other course.
8. The attacker saves the changes, which are then reflected in the gradebook of the targeted course.

## Impact

The successful exploitation of CVE-2026-32930 can lead to unauthorized modification of gradebook evaluation settings. This could result in inaccurate grades, unfair assessment of students, and overall compromise of the learning environment's integrity. Given that Chamilo LMS is used by educational institutions worldwide, a successful attack could affect a large number of students and teachers. The unauthorized changes could disrupt the educational process and erode trust in the system.

## Recommendation

*   Upgrade Chamilo LMS to version 1.11.38 or 2.0.0-RC.3 or later to patch CVE-2026-32930, as indicated in the overview.
*   Deploy the Sigma rule `Detect Chamilo Gradebook Edit Request` to identify attempts to exploit this IDOR vulnerability by monitoring for suspicious `editeval` parameter modifications.
*   Review web server logs for requests containing the `editeval` parameter where the associated value appears out of sequence with the user's course access, related to the Sigma rule.
