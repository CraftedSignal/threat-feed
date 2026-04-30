---
title: Breeze Cache Plugin Arbitrary File Upload Vulnerability (CVE-2026-3844)
slug: 2026-04-breeze-cache-rce
description: The Breeze Cache plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation, potentially leading to remote code execution.
date: "2024-02-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - file-upload
  - rce
vendors:
  - Cloudways
products:
  - Breeze Cache plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-3844
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3844
rules:
  - title: Detect Breeze Cache Arbitrary File Upload Attempt
    description: Detects attempts to exploit the Breeze Cache arbitrary file upload vulnerability by monitoring requests to fetch_gravatar_from_remote with suspicious file extensions in the query string.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Uploaded Files in Breeze Cache
    description: Detects attempts to access uploaded files in the wp-content/uploads/breeze/cache directory, which may indicate successful exploitation of the arbitrary file upload vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Breeze Cache plugin for WordPress, in versions up to and including 2.4.4, contains an arbitrary file upload vulnerability (CVE-2026-3844). This flaw stems from the lack of file type validation within the 'fetch_gravatar_from_remote' function. An unauthenticated attacker can exploit this vulnerability to upload arbitrary files to the affected WordPress site's server. Successful exploitation could lead to remote code execution on the server. It is important to note that the vulnerability can only be exploited if the "Host Files Locally - Gravatars" setting is enabled within the Breeze Cache plugin. This setting is disabled by default, reducing the attack surface. Defenders should prioritize identifying potentially compromised systems running vulnerable versions of Breeze Cache with the "Host Files Locally - Gravatars" option enabled.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site running a vulnerable version (<= 2.4.4) of the Breeze Cache plugin.
2. The attacker confirms the "Host Files Locally - Gravatars" option is enabled on the target WordPress site.
3. The attacker crafts a malicious HTTP request targeting the 'fetch_gravatar_from_remote' function. This request contains a payload designed to upload an arbitrary file to the server.
4. Due to the missing file type validation, the server accepts the malicious file upload without proper sanitization. The uploaded file can be a PHP file, a web shell, or another executable type.
5. The attacker determines the location where the file has been saved by the plugin.
6. The attacker sends an HTTP request to the uploaded file's location, triggering its execution on the server.
7. The malicious file executes, granting the attacker remote code execution capabilities on the web server.
8. The attacker can then perform actions such as installing malware, stealing sensitive data, or further compromising the server and network.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to upload arbitrary files to a vulnerable WordPress server. This can lead to complete compromise of the server, allowing for remote code execution. The attacker can then pivot to other systems, steal sensitive information, or cause significant disruption. While the "Host Files Locally - Gravatars" option is disabled by default, any instance where this option is enabled is at critical risk.

## Recommendation

*   Upgrade the Breeze Cache plugin to the latest version to patch CVE-2026-3844.
*   Disable the "Host Files Locally - Gravatars" setting in the Breeze Cache plugin if it is enabled.
*   Deploy the Sigma rules provided below to your SIEM to detect potential exploitation attempts.
*   Monitor web server logs for suspicious file uploads and requests to unusual file extensions using the provided Sigma rules.
*   Implement strict file upload policies and validation mechanisms on all web applications to prevent arbitrary file uploads.
