---
title: Algernon Server-Side Script Source Disclosure via NTFS Filename Manipulation (CVE-2026-52792)
slug: 2026-07-algernon-source-disclosure
description: Algernon, when running on a Windows host, is vulnerable to CVE-2026-52792, allowing an unauthenticated attacker to exploit its `filepath.Ext()` processing to bypass script execution and obtain the raw source code of server-side scripts by appending NTFS-equivalent suffixes (such as `::$DATA`, trailing dot, or trailing space) to the URL, thereby leaking sensitive embedded secrets like database credentials, API keys, and `SetCookieSecret` values, which can lead to authentication bypass.
date: "2026-07-03T11:12:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webserver
  - vulnerability
  - code-disclosure
  - server-side-vulnerability
  - windows
vendors:
  - xyproto
products:
  - Algernon (<= 1.17.8)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Algernon, when running on a Windows host, is vulnerable to server-side script source disclosure... An unauthenticated client appends one of these suffixes to any server-side script on a public path and receives its raw source instead of executed output.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: leaking embedded secrets such as database credentials and the `SetCookieSecret` value.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mm6c-5j6x-hq8m
rules:
  - title: Detects CVE-2026-52792 Exploitation - Algernon Source Disclosure
    description: Detects attempts to exploit CVE-2026-52792 in Algernon on Windows by requesting server-side scripts with NTFS-equivalent filename suffixes (e.g., '::$DATA', trailing dot, or trailing space) resulting in raw source code disclosure.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-52792 exposes Algernon, a web server written in Go, to a critical server-side script source disclosure vulnerability when deployed on Windows operating systems. Affecting versions up to and including 1.17.8, this flaw stems from Algernon's file handler, which incorrectly interprets NTFS-equivalent filenames (e.g., `x.lua::$DATA`, `x.lua.`, `x.lua `). An unauthenticated client can append these suffixes to the URL of any server-side script (such as `.lua`, `.tl`, `.po2`) located on a public path. Instead of executing the script as intended, Algernon serves its raw source code, directly exposing embedded secrets like database connection strings, API keys, and the `SetCookieSecret` value. This vulnerability was published on 2026-07-02 and significantly impacts the confidentiality of sensitive information, potentially enabling attackers to forge session cookies and bypass authentication mechanisms.

## Attack Chain

1.  **Reconnaissance/Target Identification**: An attacker identifies an Algernon web server instance running on a Windows host that is publicly accessible via HTTP/HTTPS.
2.  **Public Script Enumeration**: The attacker discovers or guesses the path to a server-side script (e.g., `index.lua`, `api.tl`) that is configured on a public path and is designed for execution rather than direct serving.
3.  **Bypass Execution**: The attacker crafts a specially formatted HTTP GET request by appending an NTFS-equivalent suffix (e.g., `::$DATA`, a trailing dot `.`, or a trailing space `%20`) to the script's URL (e.g., `http://target/index.lua::$DATA`).
4.  **Source Code Disclosure**: Due to the vulnerability, Algernon's `filepath.Ext()` function fails to recognize the script's true extension, bypassing the execution logic.
5.  **Raw File Retrieval**: Algernon proceeds to open the manipulated filename using `os.Open()`, which, on Windows, resolves the NTFS-equivalent name back to the original script file.
6.  **Secret Exfiltration**: The server streams the raw contents of the script file directly to the attacker, exposing any embedded secrets such as database credentials (`POSTGRES("postgres://app:S3cr3t@db/prod")`) or `SetCookieSecret("hardcoded-session-key")` values.

## Impact

The successful exploitation of CVE-2026-52792 directly compromises the confidentiality of highly sensitive information. Attackers gain access to hardcoded database credentials, API keys, and session cookie secrets. For instance, a disclosed `SetCookieSecret` value enables an unauthenticated attacker to forge session cookies, allowing them to impersonate any user and bypass authentication mechanisms entirely, leading to unauthorized access. This can result in significant data breaches, privilege escalation, and complete compromise of the affected web application and potentially connected backend systems.

## Recommendation

*   **Patch CVE-2026-52792**: Upgrade Algernon to a patched version immediately to remediate the vulnerability.
*   **Deploy Webserver Detection Rule**: Deploy the provided Sigma rule to your SIEM to detect attempts to access server-side scripts using NTFS-equivalent filenames.
*   **Review `SetCookieSecret` Usage**: Audit all server-side scripts for hardcoded `SetCookieSecret` values and other sensitive credentials. Ensure these are retrieved from secure environment variables or a secrets management system.
*   **Enable Webserver Logging**: Ensure detailed webserver access logs (`webserver` category) are collected and ingested into your SIEM, including full request paths, HTTP methods, and response status codes, to enable effective detection.
