---
title: WWBN AVideo Arbitrary File Deletion via Path Traversal (CVE-2026-33293)
slug: 2024-01-19-avideo-arbitrary-file-deletion
description: WWBN AVideo versions before 26.0 are vulnerable to arbitrary file deletion due to insufficient sanitization of the `deleteDump` parameter in `plugin/CloneSite/cloneServer.json.php`, allowing attackers with clone credentials to delete critical files via path traversal.
date: "2024-01-19T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - file-deletion
  - path-traversal
  - web-application
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33293
rules:
  - title: AVideo Arbitrary File Deletion Attempt
    description: Detects attempts to exploit CVE-2026-33293 by identifying requests to `cloneServer.json.php` with path traversal sequences in the `deleteDump` parameter.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1190
      - T1565
    data_sources:
      - webserver
      - linux
  - title: AVideo Configuration File Deletion
    description: Detects attempts to delete the configuration.php file via unlink function.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1565
    data_sources:
      - file_event
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is susceptible to an arbitrary file deletion vulnerability (CVE-2026-33293) affecting versions prior to 26.0. The vulnerability exists in the `plugin/CloneSite/cloneServer.json.php` file, where the `deleteDump` parameter is directly passed to the `unlink()` function without proper path sanitization. This flaw allows an attacker possessing valid clone credentials to exploit path traversal sequences (e.g., `../../`) to delete arbitrary files on the server. Successful exploitation can lead to the deletion of critical application files, such as `configuration.php`, resulting in complete denial of service or enabling further attacks by removing security-critical components. Users of AVideo are advised to upgrade to version 26.0 to mitigate this vulnerability.

## Attack Chain

1. Attacker gains valid clone credentials for the AVideo platform, potentially through credential compromise or brute-forcing.
2. Attacker crafts a malicious HTTP request targeting the `plugin/CloneSite/cloneServer.json.php` endpoint.
3. The crafted request includes the `deleteDump` parameter with a path traversal payload (e.g., `../../../../configuration.php`).
4. The AVideo application receives the request and passes the unsanitized `deleteDump` parameter to the `unlink()` function.
5. The `unlink()` function attempts to delete the file specified by the path traversal payload.
6. If successful, a critical file such as `configuration.php` is deleted from the server.
7. The application experiences a denial-of-service condition due to the missing configuration file.
8. Alternatively, attackers could target security-relevant files to weaken the system's security posture and pave the way for further attacks.

## Impact

Successful exploitation of CVE-2026-33293 allows an attacker to delete arbitrary files on the AVideo server. This can lead to a complete denial-of-service condition, rendering the video platform unavailable. The deletion of configuration files like `configuration.php` is a common attack vector. Furthermore, attackers could target security-critical files to weaken the system's security and facilitate subsequent malicious activities. While specific victim counts are unknown, all instances of AVideo running versions prior to 26.0 are vulnerable.

## Recommendation

*   Upgrade AVideo installations to version 26.0 or later to remediate CVE-2026-33293.
*   Implement input validation and sanitization on all user-supplied parameters, especially those used in file system operations, to prevent path traversal attacks.
*   Monitor web server logs for suspicious requests containing path traversal sequences targeting the `plugin/CloneSite/cloneServer.json.php` endpoint. Use the provided Sigma rule to detect this activity.
*   Implement file integrity monitoring (FIM) on critical system files, such as `configuration.php`, to detect unauthorized modifications or deletions.
