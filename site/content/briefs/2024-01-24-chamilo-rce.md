---
title: Chamilo LMS Remote Code Execution via Arbitrary File Upload (CVE-2026-33704)
slug: 2024-01-24-chamilo-rce
description: Chamilo LMS versions prior to 1.11.38 are vulnerable to remote code execution via arbitrary file upload by authenticated users due to insufficient file extension filtering in the BigUpload endpoint, allowing execution of PHP code on servers configured to process .pht files.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - chamilo
  - lms
  - rce
  - cve-2026-33704
vendors:
  - Chamilo
products:
  - Chamilo LMS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-33704
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33704
rules:
  - title: Chamilo BigUpload PHT File Creation
    description: Detects creation of .pht files via Chamilo's BigUpload endpoint
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Chamilo PHT File Access
    description: Detects access to .pht files within the Chamilo web directory.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, a learning management system, is vulnerable to a critical remote code execution (RCE) flaw identified as CVE-2026-33704. This vulnerability affects versions prior to 1.11.38. An authenticated user, including students, can exploit this vulnerability by writing arbitrary content to files on the server using the BigUpload endpoint. The vulnerability lies in the insufficient filtering of file extensions. While the .php extension is filtered and converted to .phps, the .pht extension is not modified. If the Apache web server is configured to handle .pht files as PHP, this can lead to arbitrary code execution. The vulnerability was patched in version 1.11.38. Exploitation allows attackers to compromise the web server hosting the Chamilo LMS instance.

## Attack Chain

1. An attacker authenticates to the Chamilo LMS as a legitimate user (e.g., student).
2. The attacker crafts a malicious HTTP POST request targeting the `BigUpload` endpoint.
3. The request includes a `key` parameter specifying the desired filename, using a `.pht` extension.
4. The request body contains arbitrary PHP code that the attacker wants to execute on the server.
5. The Chamilo LMS application processes the request but fails to properly sanitize the `.pht` extension.
6. The application writes the attacker-controlled PHP code to a file with a `.pht` extension in the web server's document root or accessible directory.
7. The attacker sends an HTTP request to the newly created `.pht` file.
8. The Apache web server, if configured to process `.pht` files as PHP, executes the attacker-supplied code, leading to remote code execution.

## Impact

Successful exploitation of CVE-2026-33704 allows an attacker to execute arbitrary code on the Chamilo LMS server. This could lead to complete system compromise, data theft, defacement of the learning platform, or further malicious activities within the network. Given the nature of an LMS, student and faculty data, including personal information and academic records, could be exposed. There are no specific victim counts available but successful exploitation grants complete control of the Chamilo LMS instance.

## Recommendation

*   Upgrade Chamilo LMS to version 1.11.38 or later to patch CVE-2026-33704.
*   Configure the Apache web server to not execute `.pht` files as PHP. This mitigation can be implemented even without patching.
*   Deploy the Sigma rule `Chamilo_BigUpload_PHT_File_Creation` to detect the creation of `.pht` files via the `BigUpload` endpoint.
*   Monitor web server access logs for requests to `.pht` files in the Chamilo LMS web directory using the `Chamilo_PHT_File_Access` Sigma rule.
