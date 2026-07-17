---
title: Grav .htaccess Case-Insensitivity Bypass for Sensitive File Access
slug: 2026-07-grav-htaccess-bypass
description: An unauthenticated attacker can exploit a flaw in Grav prior to version 2.0.4 where the default .htaccess file's rules for blocking access to sensitive file types are case-sensitive, allowing bypass on case-insensitive filesystems (Windows, macOS, or Docker volume mounts) by requesting sensitive configuration files (e.g., .yaml, .php, .json) using uppercase or mixed-case extensions, leading to unauthorized reading of files that may contain API keys and credentials.
date: "2026-07-17T02:35:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - information-disclosure
  - grav
vendors:
  - Grav
products:
  - Grav < 2.0.4
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: read sensitive configuration files that may contain API keys and credentials
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: bypass the restrictions
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1005
    technique_name: Data from Local System
    evidence: contain API keys and credentials
    confidence_band: high
cves:
  - id: CVE-2026-62230
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62230
rules:
  - title: Detects CVE-2026-62230 Exploitation - Grav .htaccess Bypass Attempt
    description: Detects CVE-2026-62230 exploitation - unauthenticated HTTP GET requests attempting to access sensitive Grav configuration files using uppercase or mixed-case extensions to bypass .htaccess restrictions and retrieve content.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
      - discovery
    techniques:
      - T1003
      - T1083
      - T1562
    data_sources:
      - webserver
rules_count: 1
---

Grav, a popular flat-file CMS, prior to version 2.0.4, is vulnerable to a sensitive information disclosure flaw identified as CVE-2026-62230. The default `.htaccess` file, which is designed to block direct web access to sensitive file types such as `.yaml`, `.php`, and `.json`, lacks the necessary `[NC]` (No Case-insensitivity) flag in its rules. This oversight means that on operating systems with case-insensitive filesystems, including Windows (NTFS), macOS (HFS+), or environments utilizing Docker volume mounts, an unauthenticated attacker can bypass these intended restrictions. By simply requesting these sensitive files with uppercase or mixed-case extensions (e.g., `config.YAML` instead of `config.yaml`), the attacker can read their contents. This vulnerability poses a significant risk as these configuration files often contain critical data, such as API keys, database credentials, and other sensitive application settings, potentially leading to unauthorized access and further compromise.

## Attack Chain

1. An unauthenticated attacker identifies a Grav instance running on a web server deployed on a case-insensitive filesystem (e.g., Windows/NTFS, macOS/HFS+, or Docker volume mounts).
2. The attacker performs reconnaissance to identify the paths of sensitive configuration files within the Grav installation, such as `user/config/security.yaml` or other potentially sensitive `.php` and `.json` files.
3. To bypass the existing `.htaccess` restrictions, the attacker crafts an HTTP GET request targeting one of these sensitive files, intentionally modifying its extension to uppercase or mixed-case (e.g., `/user/config/security.YAML`).
4. The web server, operating on the case-insensitive filesystem, successfully resolves the file path despite the altered casing of the extension.
5. The default `.htaccess` rules, which are case-sensitive due to the missing `[NC]` flag, fail to match the uppercase or mixed-case extension, thus allowing the request to proceed instead of blocking it.
6. The web server then processes the request and serves the full content of the sensitive configuration file to the attacker, bypassing the intended access control.
7. The attacker collects and analyzes the retrieved file content to extract valuable information such as API keys, database credentials, or other sensitive configuration parameters, enabling further malicious activities.

## Impact

A successful exploitation of CVE-2026-62230 allows an unauthenticated attacker to gain unauthorized access to sensitive configuration files within a Grav installation. These files frequently store critical data such as API keys, database credentials, environment variables, and other secrets. The exposure of such information can lead to severe consequences, including unauthorized access to backend systems, data breaches, privilege escalation, and further compromise of the affected Grav application and connected services. While specific victim counts are not available, any Grav instance prior to version 2.0.4 running on Windows, macOS, or Docker with default configurations is at risk of information disclosure.

## Recommendation

* Immediately update Grav to version 2.0.4 or later to apply the official patch for CVE-2026-62230.
* Inspect existing `.htaccess` files for rules blocking access to sensitive file types (e.g., `.yaml`, `.php`, `.json`, `.env`) and ensure they include the `[NC]` (No Case-insensitivity) flag to prevent bypasses.
* Deploy the Sigma rule "Detects CVE-2026-62230 Exploitation - Grav .htaccess Bypass Attempt" to your SIEM to detect attempts to access sensitive files with altered casing.
* Monitor web server access logs (webserver category) for suspicious GET requests to sensitive file extensions (e.g., `.YAML`, `.PHP`, `.JSON`, `.ENV`, `.TXT`) that result in successful HTTP status codes (e.g., 200 OK) where they should have been blocked.
