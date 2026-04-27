---
title: Firebird FB3 Client Library Information Leak (CVE-2025-65104)
slug: 2026-04-firebird-xsqlda-leak
description: Firebird FB3 client library incorrectly handles data lengths when communicating with FB4+ servers, leading to an information leak exploitable by a local attacker.
date: "2026-04-17T18:16:30Z"
severities:
  - medium
tags:
  - cve-2025-65104
  - information-leak
  - firebird
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
cves:
  - id: CVE-2025-65104
    cvss: 7.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-65104
  - https://github.com/FirebirdSQL/firebird/releases/tag/v4.0.0
  - https://github.com/FirebirdSQL/firebird/security/advisories/GHSA-mfpr-9886-xjhg
ioc_counts:
  email: 1
rules:
  - title: Detect Firebird Client Process Creation
    description: Detects the creation of a Firebird client process, which may indicate exploitation attempts related to CVE-2025-65104.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Linux Firebird Client Process Creation
    description: Detects the creation of a Firebird client process, which may indicate exploitation attempts related to CVE-2025-65104.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2025-65104 describes an information leak vulnerability affecting the Firebird open-source relational database management system. The vulnerability exists within the FB3 versions of the client library. When an FB3 client communicates with a Firebird FB4 or higher server, the client library incorrectly places data length values into the XSQLDA (SQL Data Area) fields. This incorrect handling of data lengths can result in an information leak, potentially exposing sensitive data to an attacker…
