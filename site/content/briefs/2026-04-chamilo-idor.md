---
title: Chamilo LMS Insecure Direct Object Reference (IDOR) Vulnerability
slug: 2026-04-chamilo-idor
description: CVE-2026-32894 is an Insecure Direct Object Reference (IDOR) vulnerability in Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3, allowing authenticated teachers to delete any student's grade across the platform.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - idor
  - chamilo
  - lms
  - cve-2026-32894
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32894
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32894
  - https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-rqpg-p95v-fv98
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Chamilo LMS Grade Deletion Attempt via IDOR
    description: Detects attempts to delete grade results in Chamilo LMS via manipulation of the delete_mark or resultdelete parameters, indicative of CVE-2026-32894 exploitation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Chamilo LMS Grade Deletion Attempt via IDOR - Detailed URI
    description: Detects attempts to delete grade results in Chamilo LMS via manipulation of the delete_mark or resultdelete parameters with a specific URI pattern, indicative of CVE-2026-32894 exploitation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-32894 is a critical Insecure Direct Object Reference (IDOR) vulnerability affecting Chamilo LMS, a widely used learning management system. This vulnerability exists in versions prior to 1.11.38 and 2.0.0-RC.3. It allows any authenticated teacher account to delete student grade data, regardless of course or student ownership. The vulnerability occurs because the application fails to properly validate teacher permissions when processing requests to delete gradebook results. Successful exploitation could lead to data manipulation and privacy breaches, impacting the integrity of academic records. This vulnerability highlights the risks associated with inadequate authorization checks in web applications. Chamilo versions 1.11.38 and 2.0.0-RC.3 patch this vulnerability.

## Attack Chain

1. An attacker authenticates to the Chamilo LMS platform as a teacher.
2. The attacker navigates to the gradebook result view page.
3. The attacker identifies the `delete_mark` or `resultdelete` GET parameter used to delete grade results.
4. The attacker crafts a malicious URL by modifying the `delete_mark` or `resultdelete` parameter value to target a student's grade result outside of their assigned course.
5. The attacker sends the crafted malicious GET request to the Chamilo LMS server.
6. The server processes the request without proper ownership or scope verification, deleting the targeted grade result.
7. The targeted student's grade data is removed from the gradebook, potentially affecting their academic record.

## Impact

Successful exploitation of CVE-2026-32894 allows any authenticated teacher to arbitrarily delete grade results for any student across the entire Chamilo LMS platform. This can lead to inaccurate academic records, potentially impacting student evaluations and creating administrative overhead to correct the errors. The vulnerability affects all Chamilo LMS instances running vulnerable versions, potentially impacting thousands of educational institutions and students. The consequences of successful exploitation include data manipulation, privacy breaches, and reputational damage for the affected institutions.

## Recommendation

*   Upgrade all Chamilo LMS installations to version 1.11.38 or 2.0.0-RC.3 to patch CVE-2026-32894.
*   Monitor web server logs for suspicious GET requests containing `delete_mark` or `resultdelete` parameters targeting student grade results across different courses. Deploy the provided Sigma rule to detect this activity.
*   Implement robust authorization checks in web applications to prevent Insecure Direct Object Reference (IDOR) vulnerabilities.
*   Enable web server logging and ensure that all HTTP requests, including GET parameters, are being logged. This will aid in identifying and investigating potential exploitation attempts.
