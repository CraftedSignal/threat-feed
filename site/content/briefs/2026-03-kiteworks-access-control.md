---
title: Kiteworks Core Access Control Vulnerability (CVE-2026-23514)
slug: 2026-03-kiteworks-access-control
description: Kiteworks Core versions 9.2.0 and 9.2.1 contain an access control vulnerability (CVE-2026-23514) due to improper ownership management, allowing authenticated users to access unauthorized content, which can be mitigated by upgrading to version 9.2.2 or later.
date: "2026-03-25T15:16:37Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - access-control
  - vulnerability
  - kiteworks
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23514
  - https://github.com/kiteworks/security-advisories/security/advisories/GHSA-5gqr-cpr6-wvm5
rules:
  - title: Detect Kiteworks Unauthorized Access Attempt
    description: Detects attempts to access specific Kiteworks file paths that might indicate an exploit of CVE-2026-23514
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect Kiteworks Suspicious API Access
    description: Detects access to Kiteworks API endpoints that may indicate exploitation of CVE-2026-23514.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Kiteworks Core, a private data network (PDN) solution, is vulnerable to an access control issue in versions 9.2.0 and 9.2.1. This vulnerability, identified as CVE-2026-23514, stems from improper ownership management (CWE-282) within the application. An authenticated user can exploit this flaw to gain access to content they are not authorized to view or modify. The vulnerability was disclosed on March 25, 2026. Organizations using affected versions of Kiteworks Core are advised to upgrade to…
