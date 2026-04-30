---
title: Chamilo LMS Privilege Escalation via REST API (CVE-2026-33706)
slug: 2026-04-chamilo-privesc
description: Chamilo LMS before 1.11.38 allows authenticated users with a REST API key to escalate their privileges by modifying their user status via the update_user_from_username endpoint, potentially granting unauthorized course management capabilities.
date: "2026-04-11T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - web-application
  - CVE-2026-33706
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33706
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33706
  - https://github.com/chamilo/chamilo-lms/commit/0acf8a196307c66c049f97f5ff76cf21c4a08127
  - https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-3gqc-xr75-pcpw
rules:
  - title: Chamilo LMS Privilege Escalation Attempt (CVE-2026-33706)
    description: Detects attempts to exploit CVE-2026-33706 by monitoring POST requests to the update_user_from_username endpoint with suspicious status changes.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-33706
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Chamilo LMS Suspicious User Status Update via REST API
    description: Detects potential privilege escalation by monitoring for specific patterns in REST API requests related to user status updates in Chamilo LMS.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-33706
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-33706 affects Chamilo LMS, a learning management system. Prior to version 1.11.38, the vulnerability allows an authenticated user, specifically a student (status=5), with a valid REST API key, to elevate their privileges. This is achieved by exploiting the `update_user_from_username` endpoint in the REST API. By sending a crafted request, a student can modify their user status to Teacher/CourseManager (status=1). This privilege escalation grants the attacker the ability to create and manage courses, access sensitive data, and potentially disrupt the learning environment. The vulnerability has been patched in version 1.11.38, so upgrading is strongly recommended. This vulnerability highlights the importance of proper access controls and input validation in web applications.

## Attack Chain

1.  Attacker obtains valid credentials for a student account within the Chamilo LMS.
2.  Attacker generates a REST API key associated with their student account.
3.  Attacker crafts a malicious HTTP POST request targeting the `update_user_from_username` endpoint.
4.  The POST request includes the attacker's username and a modified status value (e.g., from 5 to 1) within the request body.
5.  The attacker sends the crafted request to the Chamilo LMS server, authenticating with their REST API key.
6.  The Chamilo LMS server, lacking proper authorization checks, updates the attacker's user status in the database.
7.  The attacker logs out and then logs back in to the Chamilo LMS.
8.  Upon re-authentication, the attacker now has Teacher/CourseManager privileges, enabling them to create and manage courses, access student data, and modify system settings.

## Impact

Successful exploitation of CVE-2026-33706 allows a student to gain administrative control over the Chamilo LMS platform. This can lead to unauthorized course creation, modification of student grades, data theft, and disruption of the learning environment. The number of potential victims depends on the number of Chamilo LMS instances running a vulnerable version (prior to 1.11.38). If successful, an attacker could potentially compromise the entire learning platform and its users.

## Recommendation

*   Upgrade Chamilo LMS to version 1.11.38 or later to patch CVE-2026-33706.
*   Implement strict access control policies and regularly audit user permissions to prevent unauthorized privilege escalation.
*   Monitor web server logs for suspicious POST requests to the `update_user_from_username` endpoint (see example Sigma rule below).
*   Deploy the provided Sigma rule to detect potential exploitation attempts in real-time.
