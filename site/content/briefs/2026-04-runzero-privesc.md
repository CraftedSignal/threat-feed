---
title: runZero Platform Superuser Privilege Escalation (CVE-2026-5373)
slug: 2026-04-runzero-privesc
description: CVE-2026-5373 is an improper privilege management vulnerability in the runZero platform that allows all-organization administrators to promote accounts to superuser status, which was fixed in version 4.0.260202.0.
date: "2026-04-07T15:17:47Z"
severities:
  - high
tags:
  - privilege-escalation
  - cve
  - runzero
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5373
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5373
  - https://help.runzero.com/docs/release-notes/#402602020
  - https://www.runzero.com/advisories/runzero-platform-su-privesc-cve-2026-5373/
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect runZero Superuser Privilege Escalation Attempt
    description: Detects attempts to exploit CVE-2026-5373 by monitoring for unexpected user role changes in runZero platform logs.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect runZero Admin API Access
    description: Detects access to runZero admin APIs, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5373 is an improper privilege management vulnerability affecting the runZero platform. This vulnerability allows administrators with "all-organization" privileges to escalate the privileges of other accounts to superuser status. This could allow a malicious or compromised administrator account to gain complete control over the runZero platform instance. The vulnerability is classified as CWE-269 (Improper Privilege Management) and has a CVSS v3.1 score of 8.1 (High). The vulnerability…
