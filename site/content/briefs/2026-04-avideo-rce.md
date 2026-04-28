---
title: WWBN AVideo Unauthenticated Remote Code Execution via test.php
slug: 2026-04-avideo-rce
description: WWBN AVideo versions up to 29.0 contain an OS Command Injection vulnerability (CVE-2026-41064) in the `test.php` file, allowing unauthenticated remote code execution due to insufficient input sanitization, especially affecting `file_get_contents` and `curl` code paths.
date: "2026-04-22T00:16:28Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-41064
  - avideo
  - rce
  - command-injection
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41064
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41064
  - https://github.com/WWBN/AVideo/commit/1e6cf03e93b5a5318204b010ea28440b0d9a5ab3
  - https://github.com/WWBN/AVideo/commit/78bccae74634ead68aa6528d631c9ec4fd7aa536
  - https://github.com/WWBN/AVideo/security/advisories/GHSA-3fpm-8rjr-v5mc
  - https://github.com/WWBN/AVideo/security/advisories/GHSA-pq8p-wc4f-vg7j
iocs:
  - type: domain
    value: httpevil[.]com
ioc_counts:
  domain: 1
rules:
  - title: Detect AVideo test.php Command Injection Attempt
    description: Detects potential command injection attempts via requests to the `test.php` endpoint in AVideo, looking for suspicious URL patterns.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo test.php file_get_contents/curl usage
    description: Detects requests using file_get_contents/curl in AVideo test.php, which are vulnerable in older versions.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is vulnerable to an unauthenticated remote code execution (RCE) flaw. This vulnerability, identified as CVE-2026-41064, exists in versions up to and including 29.0. The root cause is an incomplete fix applied to the `test.php` file. While the fix implemented `escapeshellarg` for the `wget` command, it neglected to sanitize input for the `file_get_contents` and `curl` code paths. Additionally, the URL validation regex `/^http/` is overly permissive, accepting malicious strings such as `httpevil[.]com`. Successful exploitation allows attackers to execute arbitrary commands on the server hosting the AVideo platform. The recommended remediation is to apply the updated fix detailed in commit 78bccae74634ead68aa6528d631c9ec4fd7aa536.

## Attack Chain

1.  An attacker sends a crafted HTTP request to the `test.php` endpoint.
2.  The request includes a malicious URL, designed to exploit the insufficient input validation in the `file_get_contents` or `curl` code paths. For example, using `httpevil[.]com` to bypass the regex check `/^http/`.
3.  The `test.php` script processes the request, attempting to retrieve content from the attacker-controlled URL using either `file_get_contents` or `curl`.
4.  Due to the lack of proper sanitization, the malicious URL is interpreted as an OS command.
5.  The server executes the attacker-supplied OS command.
6.  The attacker gains arbitrary code execution on the AVideo server.
7.  The attacker can then perform various malicious activities, such as installing malware, stealing sensitive data, or pivoting to other systems on the network.

## Impact

Successful exploitation of this vulnerability (CVE-2026-41064) grants unauthenticated attackers the ability to execute arbitrary code on the affected AVideo server. This can lead to complete compromise of the server, including data theft, defacement, or use as a staging ground for further attacks. Given the platform's use in video hosting, successful attacks could impact numerous users and content creators relying on the vulnerable AVideo instance. The vulnerable regex `/^http/` and unsanitized functions leave the server open to mass exploitation if exposed to the public internet.

## Recommendation

*   Apply the updated fix detailed in commit 78bccae74634ead68aa6528d631c9ec4fd7aa536 to fully address the input validation issue in `test.php`.
*   Deploy the Sigma rule "Detect AVideo test.php Command Injection Attempt" to detect exploitation attempts in web server logs.
*   Monitor web server logs for requests to `test.php` containing suspicious URLs, especially those matching the `httpevil[.]com` pattern as documented in the IOCs.
*   Implement a more robust URL validation mechanism that properly sanitizes input before passing it to `file_get_contents` or `curl`.
