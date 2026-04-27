---
title: Chamilo LMS Privilege Escalation via REST API (CVE-2026-33706)
slug: 2026-04-chamilo-privesc
description: Chamilo LMS before 1.11.38 allows authenticated users with a REST API key to escalate their privileges by modifying their user status via the update_user_from_username endpoint, potentially granting unauthorized course management capabilities.
date: "2026-04-11T12:00:00Z"
severities:
  - high
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

CVE-2026-33706 affects Chamilo LMS, a learning management system. Prior to version 1.11.38, the vulnerability allows an authenticated user, specifically a student (status=5), with a valid REST API key, to elevate their privileges. This is achieved by exploiting the `update_user_from_username` endpoint in the REST API. By sending a crafted request, a student can modify their user status to Teacher/CourseManager (status=1). This privilege escalation grants the attacker the ability to create and…
