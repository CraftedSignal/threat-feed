---
title: WWBN AVideo Unauthorized File Access and Deletion Vulnerability
slug: 2024-01-avideo-file-access
description: WWBN AVideo platform versions up to 26.0 are vulnerable to unauthorized file access and deletion, where an authenticated user with upload permissions can exploit the `objects/import.json.php` endpoint by manipulating the `fileURI` parameter to steal private video files, read adjacent text files, and delete `.mp4` and other writable files on the filesystem.
date: "2026-03-23T16:16:49Z"
type: coverage
types:
  - coverage
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

WWBN AVideo, an open-source video platform, is vulnerable to unauthorized file access and deletion in versions up to and including 26.0. The vulnerability resides in the `objects/import.json.php` endpoint, which lacks proper directory restriction on the user-controlled `fileURI` POST parameter. This allows an authenticated user with upload permissions to bypass intended security measures and access or delete files outside of their authorized scope. The vulnerability was addressed in commit e110ff542acdd7e3b81bdd02b8402b9f6a61ad78. This vulnerability allows for the potential compromise of sensitive video content and adjacent data. Exploitation can lead to data theft and potential data loss. Defenders should prioritize patching and monitoring for suspicious activity targeting this endpoint.

## Attack Chain

1. An attacker authenticates to the AVideo platform with a valid user account that possesses upload permissions.
2. The attacker crafts a malicious HTTP POST request targeting the `objects/import.json.php` endpoint.
3. The POST request includes the `fileURI` parameter, which is set to a path pointing to a target video file or adjacent text file outside the user's designated directory.
4. The server-side code processes the request without performing adequate directory restriction checks on the `fileURI` parameter.
5. If the target is a video file, the server imports the video file into the attacker's account, allowing the attacker to steal private video files.
6. If the target is a readable text file adjacent to a video, the attacker can access its contents via the import mechanism.
7. If the targeted file (either video or adjacent text file) is writable by the web server process, the attacker can trigger its deletion by including the appropriate parameters in the crafted request.
8. The attacker successfully exfiltrates the stolen video data or sensitive information from accessed files, or causes data loss due to file deletion.

## Impact

Successful exploitation of this vulnerability can lead to several critical consequences. An attacker can steal private video files belonging to other users, resulting in a breach of confidentiality and potential reputational damage. The ability to read adjacent `.txt`/`.html`/`.htm` files can expose sensitive information, such as configuration files or credentials. Furthermore, the capability to delete `.mp4` files and adjacent text files can cause data loss and disruption of service. The number of affected users depends on the specific deployment and the number of users with private video content.

## Recommendation

*   Apply the patch from commit e110ff542acdd7e3b81bdd02b8402b9f6a61ad78 to remediate CVE-2026-33493.
*   Deploy the Sigma rule to your web server logs to detect attempts to access arbitrary files using the `fileURI` parameter in requests to `objects/import.json.php`.
*   Monitor web server logs for unusual file access patterns, particularly requests to `objects/import.json.php` with `fileURI` parameters containing directory traversal sequences like "../".
