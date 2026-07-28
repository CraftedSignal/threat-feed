---
title: Arbitrary File Deletion Vulnerability in WordPress Better Messages Plugin
slug: 2026-07-wordpress-better-messages-file-deletion
description: A path traversal vulnerability, CVE-2026-16585, in the Better Messages - Chat Rooms, Group Chat, Private Messages & AI Chat Bots plugin for WordPress allows authenticated administrators to delete arbitrary files on the server by bypassing file path validation, potentially leading to remote code execution.
date: "2026-07-28T07:19:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - web-vulnerability
  - path-traversal
  - rce
  - file-deletion
vendors:
  - Better Messages
products:
  - Better Messages – Chat Rooms, Group Chat, Private Messages & AI Chat Bots < 2.15.19
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php)
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: can easily lead to remote code execution when the right file is deleted (such as wp-config.php)
    confidence_band: med
cves:
  - id: CVE-2026-16585
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16585
rules:
  - title: Detects CVE-2026-16585 Exploitation - Better Messages Plugin Path Traversal
    description: Detects exploitation attempts for CVE-2026-16585, an arbitrary file deletion vulnerability in the Better Messages WordPress plugin, by identifying requests to delete_sticker with path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1070.004
      - T1499
    data_sources:
      - webserver
rules_count: 1
---

A critical path traversal vulnerability, identified as CVE-2026-16585, affects all versions up to and including 2.15.19 of the Better Messages - Chat Rooms, Group Chat, Private Messages & AI Chat Bots plugin for WordPress. This flaw stems from insufficient file path validation within the `delete_sticker` function, which an authenticated attacker with administrator-level access can exploit. By crafting a URL that leverages path traversal sequences like `../`, an attacker can bypass the intended restrictions meant to limit deletions to the uploads directory. This bypass is possible because the `normalize_sticker` function, which processes URLs, uses `esc_url_raw()` which fails to strip these traversal sequences, allowing the malicious payload to be stored verbatim. Successful exploitation can lead to arbitrary file deletion on the server, including critical files such as `wp-config.php`, which can subsequently facilitate remote code execution.

## Attack Chain

1. An attacker obtains or leverages existing administrator-level credentials for a WordPress instance running the vulnerable Better Messages plugin.
2. The authenticated attacker crafts a malicious HTTP POST request targeting the plugin's `delete_sticker` functionality, likely via `admin-ajax.php`.
3. The crafted request includes a URL parameter for the file path containing path traversal sequences (e.g., `../../`) embedded after a legitimate base uploads URL.
4. The `normalize_sticker` function processes this URL, but its use of `esc_url_raw()` fails to sanitize or strip the `../` sequences, allowing the traversal payload to persist.
5. The `delete_sticker` function then attempts to delete a file based on this manipulated path, which bypasses the intended directory restrictions.
6. The vulnerability allows the function to delete arbitrary files on the WordPress server, outside the plugin's designated uploads directory.
7. Deletion of critical system files, such as `wp-config.php`, can lead to a denial of service, loss of sensitive data, or enable further exploitation, including remote code execution.

## Impact

Successful exploitation of CVE-2026-16585 leads to arbitrary file deletion on the affected WordPress server. An attacker, once authenticated as an administrator, can remove critical system files like `wp-config.php`. This can result in a denial of service for the website, expose sensitive configuration details, or potentially enable subsequent remote code execution, granting the attacker full control over the compromised WordPress instance. The vulnerability affects a widely used plugin, exposing a broad range of WordPress sites to this severe risk.

## Recommendation

* Patch the Better Messages - Chat Rooms, Group Chat, Private Messages & AI Chat Bots plugin to a version greater than 2.15.19 immediately to remediate CVE-2026-16585.
* Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect exploitation attempts.
* Ensure web server access logs are collected for the `webserver` category, including full URL paths and query parameters, to enable detection of path traversal attempts.
