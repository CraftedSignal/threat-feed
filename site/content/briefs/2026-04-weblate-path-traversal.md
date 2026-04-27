---
title: Weblate Path Traversal Vulnerability in ZIP Download Feature (CVE-2026-34242)
slug: 2026-04-weblate-path-traversal
description: Weblate versions before 5.17 are vulnerable to path traversal due to improper verification of downloaded files in the ZIP download feature, potentially allowing attackers to access files outside the intended repository.
date: "2026-04-15T19:16:35Z"
severities:
  - medium
tags:
  - weblate
  - path-traversal
  - zip-archive
  - cve-2026-34242
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-34242
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34242
  - https://github.com/WeblateOrg/weblate/commit/5db3a2a2e047ecaab627a8731cd744a30b2f51d3
  - https://github.com/WeblateOrg/weblate/security/advisories/GHSA-hv99-mxm5-q397
rules:
  - title: Detect ZIP Archive Downloads with Suspicious Filenames
    description: Detects downloads of ZIP archives that contain filenames with '..' or other path traversal indicators, which may be indicative of CVE-2026-34242 exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
  - title: Detect Attempted Path Traversal via HTTP Request
    description: Detects HTTP requests containing '..' sequences that may indicate path traversal attempts.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Weblate, a web-based localization tool, has a path traversal vulnerability (CVE-2026-34242) affecting versions prior to 5.17. The vulnerability exists within the ZIP download feature, where the application fails to adequately verify downloaded files. This can allow an attacker to craft a malicious ZIP archive containing symbolic links that, when extracted by a user or the application itself, can lead to files outside of the intended repository being accessed. The vulnerability was reported and…
