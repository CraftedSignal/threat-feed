---
title: AVideo Remote Code Execution via Locale File Write
slug: 2024-01-23-avideo-rce
description: AVideo versions 29.0 and prior are vulnerable to remote code execution due to unsanitized file path construction in the locale save endpoint, allowing arbitrary PHP file writes by authenticated administrators or those who can CSRF them.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - rce
  - cve-2026-40909
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-40909
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40909
rules:
  - title: AVideo Locale Save Arbitrary File Write
    description: Detects potential exploitation of CVE-2026-40909 in AVideo via directory traversal in the locale save endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: AVideo Shell Upload via Locale Save
    description: Detects a potential shell upload to the webroot via the AVideo locale save endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open source video platform, is susceptible to remote code execution in versions 29.0 and earlier. The vulnerability, identified as CVE-2026-40909, stems from the `locale/save.php` endpoint. This endpoint constructs a file path by directly concatenating the `$_POST['flag']` parameter into the path without sanitization at line 30. Subsequently, the `$_POST['code']` parameter is written verbatim to the generated path via `fwrite()` at line 40. This lack of input validation allows an authenticated administrator, or an attacker capable of executing a cross-site request forgery (CSRF) attack against an administrator, to write arbitrary PHP files to any writable location on the filesystem, leading to arbitrary code execution. The vulnerable versions use `SameSite=None` for cookies and lack CSRF token checks, exacerbating the risk. The patch is available in commit 57f89ffbc27d37c9d9dd727212334846e78ac21a.

## Attack Chain

1. An attacker authenticates to the AVideo platform as an administrator or gains the ability to perform actions as an administrator (e.g., through CSRF).
2. The attacker crafts a malicious HTTP POST request targeting the `/locale/save.php` endpoint.
3. In the POST request, the attacker sets the `flag` parameter to a string containing directory traversal sequences (e.g., `../../`) to navigate to a writable directory outside of the intended `locale/` directory.
4. The attacker sets the `code` parameter to arbitrary PHP code that they want to execute on the server. This code can include web shells or other malicious payloads.
5. The server receives the POST request and, due to the lack of sanitization, constructs a file path based on the attacker-controlled `flag` parameter.
6. The server writes the contents of the `code` parameter to the file path constructed in the previous step, creating a PHP file containing the attacker's malicious code.
7. The attacker accesses the newly created PHP file via a web request, triggering the execution of the injected PHP code.
8. The attacker achieves remote code execution on the AVideo server, enabling them to perform actions such as installing malware, accessing sensitive data, or compromising the entire system.

## Impact

Successful exploitation of CVE-2026-40909 allows an attacker to execute arbitrary PHP code on the AVideo server. This can lead to complete system compromise, including data theft, installation of malware, and denial of service. Given the nature of AVideo as a video platform, a successful attack could also result in the defacement of the website or the distribution of malicious content to users. The number of potential victims is directly proportional to the number of AVideo installations running vulnerable versions.

## Recommendation

*   Apply the patch from commit 57f89ffbc27d37c9d9dd727212334846e78ac21a or upgrade to a version of AVideo greater than 29.0 to remediate CVE-2026-40909.
*   Deploy the Sigma rule "AVideo Locale Save Arbitrary File Write" to detect attempts to exploit this vulnerability via directory traversal in the `flag` parameter within web server logs.
*   Monitor web server logs for requests to `/locale/save.php` containing directory traversal sequences (`../`) in the POST parameters to identify potential exploitation attempts.
