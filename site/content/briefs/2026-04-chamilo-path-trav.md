---
title: Chamilo LMS Path Traversal Vulnerability (CVE-2026-31939)
slug: 2026-04-chamilo-path-trav
description: A path traversal vulnerability (CVE-2026-31939) in Chamilo LMS versions prior to 1.11.38 allows authenticated attackers to delete arbitrary files via unsanitized user input in the 'test' parameter of savescores.php.
date: "2026-04-11T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - file-deletion
  - chamilo-lms
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-31939
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31939
  - https://github.com/chamilo/chamilo-lms/commit/4dddcc19d36119da27b7c49eb84a035800abae78
  - https://github.com/chamilo/chamilo-lms/releases/tag/v1.11.38
  - https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-8q8c-v75x-q2hx
rules:
  - title: Detect Chamilo LMS Path Traversal Attempt in savescores.php
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-31939) in Chamilo LMS by monitoring HTTP requests to savescores.php containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Chamilo LMS savescores.php POST request with suspicious file extensions
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-31939) in Chamilo LMS by monitoring POST requests to savescores.php containing suspicious file extensions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, a learning management system, is vulnerable to a path traversal vulnerability (CVE-2026-31939) affecting versions prior to 1.11.38. This vulnerability resides in the `main/exercise/savescores.php` script. The vulnerability arises because the application directly concatenates user-supplied input from the `$_REQUEST['test']` parameter into a filesystem path without proper sanitization, canonicalization, or traversal checks. This allows an attacker to manipulate the path and potentially delete arbitrary files on the server. Successful exploitation requires an authenticated user with access to the vulnerable functionality. Organizations using affected versions of Chamilo LMS are at risk of data loss and potential system compromise.

## Attack Chain

1.  An authenticated user accesses the `main/exercise/savescores.php` script within the Chamilo LMS application.
2.  The application retrieves the value of the `test` parameter from the `$_REQUEST` array.
3.  The application concatenates this user-supplied value directly into a file system path without proper sanitization or validation.
4.  The application then attempts to delete the file specified by the constructed path using a function such as `unlink()`.
5.  An attacker crafts a malicious `test` parameter containing path traversal sequences (e.g., `../../`) to navigate outside the intended directory.
6.  The application, without proper checks, uses the manipulated path to delete a file outside of the designated exercise directory.
7.  The attacker successfully deletes arbitrary files on the server, potentially including sensitive configuration files or other critical data.

## Impact

Successful exploitation of CVE-2026-31939 allows an attacker to delete arbitrary files on the Chamilo LMS server. This can lead to data loss, system instability, and potential compromise of the entire system. The CVSS v3.1 score of 8.3 (HIGH) reflects the potential for significant impact, with confidentiality, integrity, and availability all being affected. The number of victims depends on the deployment size and user base of the affected Chamilo LMS instances.

## Recommendation

*   Upgrade Chamilo LMS to version 1.11.38 or later to patch CVE-2026-31939, as indicated in the advisory [https://github.com/chamilo/chamilo-lms/releases/tag/v1.11.38](https://github.com/chamilo/chamilo-lms/releases/tag/v1.11.38).
*   Implement input validation and sanitization on all user-supplied input, especially the `test` parameter in `main/exercise/savescores.php`, to prevent path traversal attacks.
*   Monitor web server logs for suspicious requests to `main/exercise/savescores.php` containing path traversal sequences (e.g., `../`, `..\\`), using the provided Sigma rule as a guide.
*   Implement file system access controls to limit the permissions of the web server process to only the necessary directories.
