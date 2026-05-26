---
title: Kirby CMS Pre-Authentication Path Traversal and PHP File Inclusion
slug: 2026-05-kirby-path-traversal
description: Kirby CMS versions 5.3.0 through 5.4.0 are vulnerable to pre-authentication path traversal, allowing an attacker to include arbitrary PHP files with the filename `index.php`, potentially leading to sensitive information disclosure or malicious actions due to insufficient validation of the provided user ID during user lookup.
date: "2026-05-26T23:58:21Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - path-traversal
  - php-file-inclusion
  - kirby-cms
  - CVE-2026-44177
vendors:
  - Kirby
products:
  - cms (>= 5.3.0, <= 5.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-9hx7-c53c-v6x8
  - https://github.com/getkirby/kirby/releases/tag/5.4.1
rules:
  - title: Detect Kirby CMS Path Traversal Attempt
    description: Detects CVE-2026-44177 exploitation — Attempts to exploit path traversal vulnerability in Kirby CMS by detecting `../` sequences in HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect PHP File Inclusion via Crafted User ID
    description: Detects CVE-2026-44177 exploitation — PHP file inclusion attempts in Kirby CMS by monitoring for requests that access 'index.php' after a path traversal attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Kirby CMS versions 5.3.0 to 5.4.0 are vulnerable to a path traversal vulnerability. This flaw stems from insufficient validation of user IDs during user lookup, a performance improvement introduced in version 5.3.0. The vulnerability is pre-authentication, meaning no prior access is required. By exploiting this flaw, attackers can include arbitrary PHP files named `index.php`, potentially gaining the ability to execute malicious code or disclose sensitive information. This issue impacts the authentication API, users API, and any other instance where `$users->find()` is used with a request-provided email or user ID. Successful exploitation allows attackers to probe for the existence of arbitrary directories, enabling fingerprinting of the server setup, installed plugins, and content structure.

## Attack Chain

1. An attacker sends a request to the authentication API, users API, or any endpoint using `$users->find()` with a crafted user ID.
2. The crafted user ID contains path traversal sequences (e.g., `../`) to navigate outside the intended user account directory.
3. Kirby CMS constructs a file path using the manipulated user ID to locate the user's account directory within `site/accounts/`.
4. Due to insufficient validation, the path traversal sequences are not properly sanitized.
5. The application attempts to include an `index.php` file from the traversed path.
6. If a file named `index.php` exists in the traversed directory, it is included and executed by the PHP interpreter.
7. Depending on the contents of the included `index.php`, sensitive information may be disclosed or arbitrary code may be executed.
8. The attacker leverages the code execution to further compromise the system or exfiltrate data.

## Impact

The path traversal vulnerability in Kirby CMS versions 5.3.0 through 5.4.0 can lead to arbitrary PHP file inclusion, allowing attackers to execute malicious code or disclose sensitive data. Successful exploitation enables attackers to probe the existence of arbitrary directories on the server, facilitating fingerprinting of the server setup, installed plugins, and content structure. This vulnerability is rated high severity because it's pre-authentication and enables full system compromise if a vulnerable `index.php` file is reachable.

## Recommendation

*   Upgrade to Kirby CMS version 5.4.1 or later to patch the vulnerability as advised in the [Kirby 5.4.1](https://github.com/getkirby/kirby/releases/tag/5.4.1) release notes.
*   Deploy the Sigma rule `Detect Kirby CMS Path Traversal Attempt` to detect exploitation attempts by monitoring HTTP requests with path traversal sequences.
*   Monitor web server logs for requests containing `../` sequences in the user ID or email parameters to identify potential path traversal attempts.
