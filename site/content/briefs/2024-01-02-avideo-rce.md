---
title: WWBN AVideo Remote Code Execution via Locale Save Path Traversal
slug: 2024-01-02-avideo-rce
description: WWBN AVideo is vulnerable to remote code execution due to a path traversal vulnerability in the `locale/save.php` endpoint, allowing an attacker to write arbitrary PHP files to any web-accessible directory via a maliciously crafted `flag` parameter, which can be exploited through CSRF.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - rce
  - path-traversal
  - csrf
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-6rc6-p838-686f
iocs:
  - type: url
    value: https://target/locale/save.php
  - type: url
    value: https://target/webshell.php?c=id
ioc_counts:
  url: 2
rules:
  - title: AVideo Webshell Creation via Locale Save
    description: Detects the creation of PHP files containing system commands in web-accessible directories via the locale save endpoint, indicating potential exploitation of the path traversal vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
  - title: AVideo Locale Save Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability in the AVideo locale save endpoint by identifying POST requests with malicious `flag` parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, versions 29.0 and earlier, is susceptible to a critical remote code execution (RCE) vulnerability. The flaw resides in the `locale/save.php` endpoint, which lacks proper sanitization of the `$_POST['flag']` parameter. This allows an attacker to inject path traversal sequences (e.g., `../`) and write arbitrary PHP files to any directory on the server where the web user has write permissions. The vulnerability is further exacerbated by the absence of CSRF protection on the endpoint, coupled with the application's use of `SameSite=None` for session cookies. This allows for trivial CSRF exploitation, meaning an attacker can trigger the vulnerability simply by luring an authenticated administrator to visit a malicious webpage. Successful exploitation grants the attacker the ability to execute arbitrary PHP code, leading to full server compromise.

## Attack Chain

1. An attacker crafts a malicious HTTP POST request targeting the `/locale/save.php` endpoint.
2. The request includes a `flag` parameter containing path traversal sequences (e.g., `../../webshell`) and a `code` parameter with PHP code designed to execute arbitrary commands.
3. The AVideo application concatenates the unsanitized `flag` value with the base directory and `.php` extension, resulting in a path like `{systemRootPath}locale/../../webshell.php`.
4. The application attempts to open the file at the constructed path for writing using `fopen()`. Due to the path traversal, this escapes the intended `locale/` directory.
5. The content from the `code` parameter is written to the file using `fwrite()`, creating a PHP webshell (e.g., `webshell.php`) in a web-accessible directory, such as the web root.
6. The attacker accesses the created webshell via an HTTP GET request (e.g., `https://target/webshell.php?c=id`), passing a command to be executed as a parameter.
7. The webshell executes the attacker-supplied command using a function like `system()` or `exec()`.
8. The attacker gains arbitrary code execution on the server, enabling them to read/modify files, access the database, and potentially escalate privileges.

## Impact

Successful exploitation of this vulnerability allows for unauthenticated remote code execution, leading to full compromise of the AVideo server.  An attacker can gain complete control of the affected system, potentially impacting all user data, system configurations, and any connected services. Given the nature of AVideo as a video platform, a successful attack could also lead to the compromise and distribution of sensitive video content. The lack of CSRF protection significantly widens the attack surface, as exploitation does not require direct access to an administrator's session.

## Recommendation

*   Implement the recommended fix in the advisory by sanitizing the `flag` parameter using `basename()` to prevent path traversal, as described in the overview.
*   Implement CSRF protection by adding token validation to the `locale/save.php` endpoint and setting the `SameSite` attribute to `Strict` or `Lax` for session cookies.
*   Deploy the Sigma rule "AVideo Webshell Creation via Locale Save" to detect attempts to create PHP files with suspicious content in the web root, alerting on potential exploitation attempts.
*   Monitor web server logs for POST requests to `/locale/save.php` with `flag` parameters containing path traversal sequences (e.g., `../`), using the provided IOCs to identify and block malicious requests.
*   Update AVideo to a patched version that addresses this vulnerability.
