---
title: AVideo Arbitrary Code Execution via downloadVideoFromDownloadURL()
slug: 2024-01-avideo-rce
description: AVideo versions 26.0 and earlier are vulnerable to arbitrary code execution by exploiting the `downloadVideoFromDownloadURL()` function to save malicious PHP files in a web-accessible directory.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - rce
  - code-execution
  - vulnerability
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33717
rules:
  - title: Detect AVideo Malicious File Upload via downloadVideoFromDownloadURL
    description: Detects attempts to exploit CVE-2026-33717 by identifying requests to aVideoEncoder.json.php with an invalid resolution parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Suspicious File Upload in Cache Directory
    description: Detects creation of PHP files within the AVideo cache directory, which could indicate successful exploitation of CVE-2026-33717.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

AVideo is an open-source video platform. A critical vulnerability, CVE-2026-33717, affects AVideo versions up to and including 26.0. The vulnerability resides within the `downloadVideoFromDownloadURL()` function in `objects/aVideoEncoder.json.php`. By manipulating the `resolution` parameter, a remote attacker can bypass input validation and force the application to write arbitrary PHP code into the `videos/cache/tmpFile/` directory. Due to an early `die()` call via `forbiddenPage()`, the temporary file is not properly cleaned up, resulting in persistent arbitrary code execution on the target server. The vulnerability was patched in commit 6da79b43484099a0b660d1544a63c07b633ed3a2. Successful exploitation allows attackers to execute arbitrary code on the AVideo server.

## Attack Chain

1. The attacker sends a crafted HTTP request to the AVideo server, targeting the `downloadVideoFromDownloadURL()` function in `objects/aVideoEncoder.json.php`.
2. The attacker includes a malicious PHP file URL in the request parameters, disguised as a video file.
3. The attacker provides an invalid `resolution` parameter value designed to trigger the `forbiddenPage()` function.
4. The `downloadVideoFromDownloadURL()` function attempts to download the file from the provided URL.
5. Due to the invalid `resolution` parameter, the `forbiddenPage()` function is called, resulting in an early `die()`.
6. The premature termination prevents the intended cleanup operations, leaving the downloaded file (malicious PHP) in the `videos/cache/tmpFile/` directory.
7. The attacker accesses the uploaded PHP file via a direct HTTP request to `videos/cache/tmpFile/<malicious_file>.php`.
8. The server executes the PHP code, granting the attacker arbitrary code execution on the AVideo server.

## Impact

Successful exploitation of CVE-2026-33717 allows an attacker to execute arbitrary code on the AVideo server. This could lead to complete system compromise, including data theft, modification, or destruction, as well as the potential for denial-of-service attacks. The specific number of vulnerable installations is unknown, but any AVideo instance running a version up to and including 26.0 is susceptible to this attack.

## Recommendation

*   Apply the patch from commit 6da79b43484099a0b660d1544a63c07b633ed3a2 or upgrade to a version of AVideo greater than 26.0 to remediate CVE-2026-33717.
*   Deploy the Sigma rule `Detect AVideo Malicious File Upload via downloadVideoFromDownloadURL` to identify attempts to exploit this vulnerability (log source: webserver).
*   Monitor web server logs for requests containing the string `aVideoEncoder.json.php` and an invalid `resolution` parameter (log source: webserver).
*   Implement strict input validation on the `resolution` parameter to prevent arbitrary values (code remediation).
