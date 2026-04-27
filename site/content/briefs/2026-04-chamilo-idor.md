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

CVE-2026-32894 is a critical Insecure Direct Object Reference (IDOR) vulnerability affecting Chamilo LMS, a widely used learning management system. This vulnerability exists in versions prior to 1.11.38 and 2.0.0-RC.3. It allows any authenticated teacher account to delete student grade data, regardless of course or student ownership. The vulnerability occurs because the application fails to properly validate teacher permissions when processing requests to delete gradebook results. Successful…
