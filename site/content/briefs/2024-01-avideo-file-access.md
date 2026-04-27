---
title: WWBN AVideo Unauthorized File Access and Deletion Vulnerability
slug: 2024-01-avideo-file-access
description: WWBN AVideo platform versions up to 26.0 are vulnerable to unauthorized file access and deletion, where an authenticated user with upload permissions can exploit the `objects/import.json.php` endpoint by manipulating the `fileURI` parameter to steal private video files, read adjacent text files, and delete `.mp4` and other writable files on the filesystem.
date: "2026-03-23T16:16:49Z"
severities:
  - high
tags:
  - avideo
  - file-access
  - vulnerability
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33493
rules:
  - title: AVideo Unauthorized File Import via fileURI
    description: Detects attempts to exploit CVE-2026-33493 by abusing the fileURI parameter in objects/import.json.php to access arbitrary files.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1583.001
    data_sources:
      - webserver
      - linux
  - title: AVideo Directory Traversal in fileURI Parameter
    description: Detects directory traversal attempts in the fileURI parameter of objects/import.json.php.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1583.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is vulnerable to unauthorized file access and deletion in versions up to and including 26.0. The vulnerability resides in the `objects/import.json.php` endpoint, which lacks proper directory restriction on the user-controlled `fileURI` POST parameter. This allows an authenticated user with upload permissions to bypass intended security measures and access or delete files outside of their authorized scope. The vulnerability was addressed in commit…
