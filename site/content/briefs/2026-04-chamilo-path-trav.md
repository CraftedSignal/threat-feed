---
title: Chamilo LMS Path Traversal Vulnerability (CVE-2026-31939)
slug: 2026-04-chamilo-path-trav
description: A path traversal vulnerability (CVE-2026-31939) in Chamilo LMS versions prior to 1.11.38 allows authenticated attackers to delete arbitrary files via unsanitized user input in the 'test' parameter of savescores.php.
date: "2026-04-11T12:00:00Z"
severities:
  - high
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
ioc_counts:
  email: 1
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

Chamilo LMS, a learning management system, is vulnerable to a path traversal vulnerability (CVE-2026-31939) affecting versions prior to 1.11.38. This vulnerability resides in the `main/exercise/savescores.php` script. The vulnerability arises because the application directly concatenates user-supplied input from the `$_REQUEST['test']` parameter into a filesystem path without proper sanitization, canonicalization, or traversal checks. This allows an attacker to manipulate the path and…
