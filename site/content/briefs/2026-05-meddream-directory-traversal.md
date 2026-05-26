---
title: Softneta MedDream PACS Server Premium Directory Traversal Vulnerability (CVE-2018-25374)
slug: 2026-05-meddream-directory-traversal
description: Softneta MedDream PACS Server Premium 6.7.1.1 contains a directory traversal vulnerability, tracked as CVE-2018-25374, allowing unauthenticated attackers to read arbitrary files by manipulating the path parameter in requests to nocache.php.
date: "2026-05-26T14:15:51Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - directory-traversal
  - web-application
  - CVE-2018-25374
vendors:
  - Softneta
products:
  - MedDream PACS Server Premium 6.7.1.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25374
    cvss: 7.5
    epss: 0.0052
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25374
  - https://www.exploit-db.com/exploits/45347
  - https://www.softneta.com/products/meddream-pacs-server/downloads.html
  - https://www.vulncheck.com/advisories/softneta-meddream-pacs-server-premium-directory-traversal
rules:
  - title: Detect MedDream PACS Directory Traversal via nocache.php
    description: Detects CVE-2018-25374 exploitation — attempts to exploit directory traversal in Softneta MedDream PACS Server Premium via the nocache.php endpoint with encoded directory traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2018-25374 is a directory traversal vulnerability affecting Softneta MedDream PACS Server Premium version 6.7.1.1. This vulnerability allows unauthenticated attackers to read arbitrary files on the server. By manipulating the `path` parameter in requests to the `nocache.php` endpoint with encoded backslash sequences, attackers can bypass directory traversal protections and access sensitive files, potentially including system configuration files and password files. The vulnerability was reported on 2026-05-25 and poses a significant risk as it allows unauthorized access to sensitive information without requiring authentication. Exploitation is straightforward, increasing the likelihood of successful attacks.

## Attack Chain

1. An unauthenticated attacker identifies a MedDream PACS Server Premium 6.7.1.1 instance.
2. The attacker crafts a malicious HTTP GET request targeting the `nocache.php` endpoint.
3. The attacker injects a directory traversal payload into the `path` parameter using encoded backslash sequences (e.g., `%2E%2E%2F` for `../`).
4. The server processes the request without proper sanitization of the `path` parameter.
5. The server attempts to read the file specified by the manipulated path, traversing directories outside of the intended web root.
6. If successful, the server returns the contents of the targeted file in the HTTP response.
7. The attacker retrieves sensitive information, such as configuration files or password hashes.

## Impact

Successful exploitation of CVE-2018-25374 allows unauthenticated attackers to read arbitrary files on the affected server. This can lead to the disclosure of sensitive information, including system credentials, configuration details, and patient data. The vulnerability affects Softneta MedDream PACS Server Premium 6.7.1.1, potentially impacting healthcare organizations that rely on this software for medical image archiving and communication. Compromise of such data can lead to regulatory fines, reputational damage, and potential legal liabilities.

## Recommendation

*   Deploy the Sigma rule `Detect MedDream PACS Directory Traversal via nocache.php` to identify exploitation attempts targeting CVE-2018-25374 by monitoring for encoded backslash sequences in requests to `nocache.php`.
*   Apply appropriate input validation and sanitization to the `path` parameter in `nocache.php` to prevent directory traversal, as outlined in the CVE-2018-25374 description.
*   Review the vendor's website for potential patches or mitigation steps for CVE-2018-25374.
