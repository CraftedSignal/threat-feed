---
title: 'CVE-2022-50944: Aero CMS 0.0.1 PHP Code Injection Vulnerability'
slug: 2026-05-aero-cms-php-code-injection
description: Aero CMS 0.0.1 is vulnerable to PHP code injection (CVE-2022-50944), allowing an authenticated attacker to execute arbitrary PHP code by uploading malicious files through the image parameter, leading to remote code execution on the server.
date: "2026-05-10T13:22:02Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - code-injection
  - php
  - web-application
  - cve-2022-50944
vendors:
  - MegaTKC
products:
  - Aero CMS 0.0.1
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2022-50944
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-50944
  - https://github.com/MegaTKC/AeroCMS
  - https://www.exploit-db.com/exploits/51085
  - https://www.vulncheck.com/advisories/aero-cms-php-code-injection-via-posts-php
rules:
  - title: Detect Suspicious PHP File Upload via Image Parameter
    description: Detects CVE-2022-50944 exploitation — PHP file upload via the image parameter in the /admin/posts.php endpoint, indicating a potential PHP code injection attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Direct Access to Suspicious Uploaded PHP Files
    description: Detects attempts to directly access PHP files uploaded to the webserver, potentially indicating successful exploitation of CVE-2022-50944.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
rules_count: 2
---

Aero CMS 0.0.1 is susceptible to a PHP code injection vulnerability identified as CVE-2022-50944. This flaw allows authenticated attackers to inject and execute arbitrary PHP code on the affected server. The vulnerability is triggered by uploading a malicious PHP file through the `image` parameter when adding or modifying a post. Specifically, an attacker can send a crafted request to the `/admin/posts.php` endpoint with the `source=add_post` parameter, containing PHP code embedded within an image file. Successful exploitation allows the attacker to gain remote code execution, potentially leading to full system compromise. This poses a significant risk to organizations using Aero CMS 0.0.1, as it could enable data theft, service disruption, or further malicious activities.

## Attack Chain

1.  Attacker authenticates to the Aero CMS application.
2.  Attacker crafts a malicious PHP file containing code to be executed on the server.
3.  Attacker accesses the `/admin/posts.php` endpoint with the `source=add_post` parameter.
4.  Attacker uploads the malicious PHP file through the `image` parameter in a POST request to `/admin/posts.php`.
5.  The application saves the uploaded file to a directory accessible by the webserver.
6.  The attacker crafts a request to directly access the uploaded PHP file via HTTP.
7.  The webserver executes the PHP code within the uploaded file.
8.  Attacker achieves remote code execution on the server.

## Impact

Successful exploitation of this vulnerability (CVE-2022-50944) allows an attacker to execute arbitrary PHP code on the server hosting Aero CMS 0.0.1. This could lead to complete compromise of the affected system, including the ability to read sensitive data, modify website content, install malware, or pivot to other systems on the network. The vulnerability has a CVSS v3.1 score of 8.8, indicating a high severity. While the number of victims is unknown, any system running the vulnerable version of Aero CMS is at risk if authentication is compromised.

## Recommendation

*   Upgrade to a patched version of Aero CMS if available; otherwise, discontinue use of the product.
*   Implement strict input validation on the `image` parameter to prevent the upload of PHP files to mitigate CVE-2022-50944.
*   Deploy the Sigma rule `Detect Suspicious PHP File Upload via Image Parameter` to identify attempts to upload malicious PHP files to the `/admin/posts.php` endpoint.
*   Monitor web server logs for suspicious requests to `/admin/posts.php` with the `source=add_post` parameter and PHP files uploaded through the `image` parameter to identify potential exploitation attempts, as described in the attack chain.
