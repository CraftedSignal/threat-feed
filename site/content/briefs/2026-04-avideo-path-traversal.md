---
title: WWBN AVideo Unauthenticated Path Traversal Vulnerability (CVE-2026-41058)
slug: 2026-04-avideo-path-traversal
description: WWBN AVideo versions 29.0 and below contain a path traversal vulnerability (CVE-2026-41058) in the CloneSite functionality, allowing unauthenticated attackers to delete arbitrary files via manipulation of the `deleteDump` parameter.
date: "2026-04-22T12:00:00Z"
severities:
  - high
tags:
  - path traversal
  - cve-2026-41058
  - avideo
  - webserver
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-41058
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41058
  - https://github.com/WWBN/AVideo/commit/3c729717c26f160014a5c86b0b6accdbd613e7b2
rules:
  - title: Detect AVideo Path Traversal Attempt
    description: Detects potential path traversal attempts targeting the AVideo CloneSite functionality by looking for '..' sequences in the deleteDump parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Arbitrary File Deletion via Path Traversal
    description: Detects potential arbitrary file deletion attempts targeting the AVideo CloneSite functionality by looking for 'unlink' and file paths.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo is an open-source video platform. Versions 29.0 and below are vulnerable to a path traversal vulnerability (CVE-2026-41058) due to an incomplete fix for the `deleteDump` parameter in the CloneSite functionality. This vulnerability allows unauthenticated attackers to delete arbitrary files on the server by injecting `../../` sequences into the GET request. The vulnerability was reported on April 21, 2026, and a fix is available in commit 3c729717c26f160014a5c86b0b6accdbd613e7b2…
