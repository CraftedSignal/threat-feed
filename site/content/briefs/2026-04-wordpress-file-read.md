---
title: Unlimited Elements for Elementor WordPress Plugin Arbitrary File Read (CVE-2026-4659)
slug: 2026-04-wordpress-file-read
description: The Unlimited Elements for Elementor plugin for WordPress is vulnerable to arbitrary file read due to insufficient path traversal sanitization, allowing authenticated attackers to read sensitive files from the WordPress host.
date: "2026-04-17T07:23:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - file-read
  - path-traversal
  - cve-2026-4659
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4659
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4659
rules:
  - title: Detect WordPress Arbitrary File Read Attempt via Path Traversal
    description: Detects attempts to exploit path traversal vulnerabilities in WordPress plugins by monitoring HTTP requests for suspicious sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Arbitrary File Read Attempt via Long Path
    description: Detects attempts to exploit arbitrary file read vulnerabilities in WordPress plugins by monitoring HTTP requests for unusually long paths.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Unlimited Elements for Elementor plugin, versions 2.0.6 and earlier, contains an arbitrary file read vulnerability (CVE-2026-4659). This vulnerability stems from inadequate sanitization of path traversal sequences within the `URLtoRelative()` and `urlToPath()` functions, particularly when combined with the ability to enable debug output. The `URLtoRelative()` function inadequately strips the base URL without properly sanitizing path traversal characters (`../`). Successful exploitation allows authenticated attackers with Author-level permissions or higher to access and read arbitrary local files on the WordPress host. This can include sensitive configuration files like `wp-config.php`, potentially exposing database credentials and other sensitive information.

## Attack Chain

1. An attacker authenticates to the WordPress application with Author-level or higher privileges.
2. The attacker identifies the `Repeater JSON/CSV URL` parameter within the Unlimited Elements widget settings.
3. The attacker crafts a malicious URL containing path traversal sequences (e.g., `http://site.com/../../../../etc/passwd`) in the `Repeater JSON/CSV URL` parameter.
4. The crafted URL is passed to the `URLtoRelative()` function, which removes the base URL but fails to sanitize the path traversal sequences.
5. The resulting path (e.g., `/../../../../etc/passwd`) is concatenated with the base path by the application.
6. The `cleanPath()` function normalizes directory separators, but does not remove traversal components, leaving the path vulnerable.
7. The application resolves the path, leading to access of the targeted file (e.g., `/etc/passwd`).
8. The attacker retrieves the contents of the arbitrary file, such as `wp-config.php`, potentially extracting sensitive information.

## Impact

Successful exploitation of this vulnerability allows attackers to read arbitrary files on the WordPress host. This can lead to the exposure of sensitive data, including database credentials, API keys, and other configuration settings stored in files like `wp-config.php`. The impact ranges from data leakage to potential full compromise of the WordPress installation and the underlying server, depending on the contents of the accessed files and the attacker's subsequent actions. The number of potentially affected WordPress sites is substantial, given the popularity of the Elementor plugin.

## Recommendation

*   Upgrade the Unlimited Elements for Elementor plugin to a version greater than 2.0.6 to patch CVE-2026-4659.
*   Monitor web server logs for HTTP requests containing path traversal sequences (`../`) in the URI, focusing on requests targeting WordPress plugins; use the provided Sigma rule to facilitate this detection.
*   Implement stricter input validation and sanitization for URL parameters within WordPress plugins, specifically when handling file paths, to prevent path traversal vulnerabilities.
