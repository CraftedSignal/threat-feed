---
title: Masteriyo LMS WordPress Plugin Privilege Escalation Vulnerability
slug: 2026-03-masteriyo-privesc
description: The Masteriyo LMS plugin for WordPress is vulnerable to privilege escalation, allowing authenticated users with student-level access or higher to gain administrator privileges by manipulating the 'InstructorsController::prepare_object_for_database' function.
date: "2026-03-26T02:16:07Z"
severities:
  - critical
tags:
  - wordpress
  - privilege-escalation
  - cve-2026-4484
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4484
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/265be0af-66a4-4636-ab81-f8e2c5a1282e?source=cve
rules:
  - title: Detect WordPress Masteriyo Plugin Privilege Escalation Attempt
    description: Detects attempts to exploit CVE-2026-4484 by modifying user roles via the Masteriyo LMS plugin's REST API.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Instructor Controller Access
    description: Detects access to the instructor controller.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Masteriyo LMS plugin, a learning management system for WordPress, contains a privilege escalation vulnerability (CVE-2026-4484) affecting versions up to and including 2.1.6. This flaw allows authenticated users, even those with low-level "Student" access, to elevate their privileges to that of an administrator. The vulnerability stems from a lack of proper authorization checks within the `InstructorsController::prepare_object_for_database` function, enabling malicious users to modify user…
