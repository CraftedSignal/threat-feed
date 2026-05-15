---
title: FrankenPHP Unsafe Unicode Handling in CGI Path Splitting Allows Execution of Non-PHP Files
slug: 2026-05-unsafe-unicode-frankenphp
description: Two distinct flaws in the `splitPos()` function in `cgi.go` allows an attacker to mislead FrankenPHP into treating a non-`.php` file as a `.php` script, leading to remote code execution where the attacker can control file content.
date: "2026-05-15T17:10:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:php:frankenphp:*:*:*:*:*:*:*:*
tags:
  - unicode
  - remote code execution
  - web server
vendors:
  - dunglas
products:
  - frankenphp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-24895
    cvss: 9.8
    epss: 0.00082
references:
  - https://github.com/advisories/GHSA-3g8v-8r37-cgjm
rules:
  - title: Detects CVE-2026-45062 Exploitation — FrankenPHP Unicode Path Traversal Attempt
    description: Detects CVE-2026-45062 exploitation — Attempts to exploit FrankenPHP vulnerability by using unicode characters in the path to bypass file extension checks
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detects CVE-2026-45062 Exploitation — FrankenPHP Non-ASCII Path Traversal Attempt
    description: Detects CVE-2026-45062 exploitation — Attempts to exploit FrankenPHP vulnerability by using Non-ASCII characters in the path to bypass file extension checks
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 2
---

The `splitPos()` function in [`cgi.go`](https://github.com/php/frankenphp/blob/main/cgi.go) in FrankenPHP versions 1.11.2 through 1.12.2 misuses `golang.org/x/text/search` with `search.IgnoreCase` when a request path contains a non-ASCII byte. This can lead to two distinct flaws where an attacker can trick FrankenPHP into interpreting non-`.php` files as PHP scripts. In scenarios where an attacker has the ability to place content into files served by FrankenPHP, like upload endpoints or file storage services, this can be exploited to achieve remote code execution by crafting a specific URL that triggers either of the identified vulnerabilities. These vulnerabilities were reported by @KC1zs4.

## Attack Chain

1. An attacker gains the ability to upload or place files with arbitrary content and names into a directory served by FrankenPHP (e.g., via a file upload endpoint).
2. The attacker crafts a malicious file with PHP code, giving it a name designed to exploit either of the `splitPos()` flaws (e.g., `shell﹒php` or `name.¡.txt`).
3. The attacker sends an HTTP request to the FrankenPHP server, targeting the uploaded file via a crafted URL.
4. The `splitPos()` function incorrectly identifies the path as a PHP file due to the Unicode equivalence or non-ASCII handling issues.
5. FrankenPHP sets the `SCRIPT_FILENAME` to the path of the attacker's malicious file.
6. The PHP interpreter processes the attacker-controlled file as a PHP script.
7. The attacker's PHP code executes within the FrankenPHP process, granting the attacker remote code execution.
8. The attacker can then perform actions such as reading sensitive data, writing files, or executing system commands on the server.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to achieve remote code execution on systems running vulnerable versions of FrankenPHP. This is possible in scenarios where the attacker can upload or place files with predictable names into directories served by FrankenPHP. The impact is similar to CVE-2026-24895, but requires the ability to control file content and name. A successful attack can lead to complete compromise of the server, including data theft, modification, and denial of service. CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H — High (8.1).

## Recommendation

*   Upgrade to a FrankenPHP version beyond 1.12.2 where the vulnerable code has been removed.
*   Deploy the following Sigma rule to detect attempts to exploit this vulnerability using Unicode characters in the file path.
*   Implement strict file naming conventions and input validation to prevent the upload of files with non-ASCII characters in their names.
*   Monitor web server logs for requests containing Unicode characters or unusual file extensions that could indicate exploitation attempts, as shown in the detection rules below.
