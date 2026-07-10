---
title: OpenMage LTS Remote Code Execution via File Upload Bypass
slug: 2024-05-openmage-rce
description: OpenMage LTS is vulnerable to remote code execution due to an incomplete file upload blocklist, allowing attackers to upload PHP-executable files and execute arbitrary code on the server.
date: "2024-05-02T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openmage
  - rce
  - file-upload
  - php
vendors:
  - OpenMage
products:
  - OpenMage LTS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-3j5q-7q7h-2hhv
rules:
  - title: Detect OpenMage Webshell Upload via .phtml
    description: Detects attempts to upload a .phtml webshell to the OpenMage media directory, indicating a potential RCE exploit.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect OpenMage Webshell Execution via .phtml
    description: Detects access to .phtml files in the OpenMage media directory, indicating potential RCE exploit post-upload.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenMage LTS is susceptible to remote code execution (RCE) due to an insufficient blocklist in its custom option file upload functionality. The application fails to adequately filter PHP-executable file extensions, only blocking `.php` and `.exe`. Attackers can bypass this restriction by uploading files with alternative PHP extensions like `.phtml`, `.phar`, `.php3`, `.php4`, `.php5`, `.php7`, and `.pht`. These uploaded files are stored in the `media/custom_options/quote/` directory. If the server configuration (e.g., Apache with PHP-FPM or Nginx with a misconfigured .phtml handler) does not restrict script execution in this directory, attackers can execute arbitrary code. Successful exploitation allows attackers to compromise the server fully. The vulnerability exists in versions of OpenMage LTS up to and including 20.16.0. The vulnerable file is `app/code/core/Mage/Catalog/Model/Product/Option/Type/File.php` within the `_validateUploadedFile()` function.

## Attack Chain

1. An attacker identifies an OpenMage LTS instance with a vulnerable configuration (e.g., Apache with PHP-FPM) and a file upload form using the custom options feature.
2. The attacker crafts a malicious PHP webshell (e.g., `shell.phtml`) designed to execute system commands via HTTP GET parameters.
3. The attacker uploads the malicious file, `shell.phtml`, through the product custom option file upload form, bypassing the insufficient file extension blocklist.
4. OpenMage stores the uploaded file in the `media/custom_options/quote/` directory, creating subdirectories based on the first two characters of the filename.
5. OpenMage calculates the filename based on the MD5 hash of the file content and stores it with the original extension (e.g., `d9bb4d647f16d9e7edfe49216140de2879.phtml`).
6. The attacker crafts a URL to access the uploaded webshell, pre-calculating the full path based on the filename and file content.
7. The attacker sends an HTTP request to the crafted URL, including a `cmd` parameter with the desired system command.
8. The server executes the PHP code in the uploaded webshell, resulting in arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve Remote Code Execution (RCE) on the OpenMage LTS server. This can lead to full server compromise, enabling attackers to exfiltrate sensitive data such as database credentials, customer PII, and payment information. Attackers can use the compromised server as a pivot point to move laterally within the internal infrastructure and potentially inject malicious code into served content, leading to a supply chain attack. The vulnerability affects versions of OpenMage LTS up to and including 20.16.0.

## Recommendation

*   Upgrade OpenMage LTS to a patched version that includes a comprehensive file extension blocklist.
*   Configure your web server (e.g., Apache, Nginx) to explicitly deny script execution in the `media/custom_options/quote/` directory to prevent execution of uploaded files.
*   Deploy the Sigma rule "Detect OpenMage Webshell Upload via .phtml" to your SIEM and tune for your environment.
*   Monitor web server access logs for requests to files with PHP-executable extensions (e.g., `.phtml`, `.phar`, `.php3`, `.php4`, `.php5`, `.php7`, `.pht`) in the `media/custom_options/quote/` directory.
*   Apply web server hardening configurations as referenced in the advisory to prevent execution of arbitrary PHP files in media directories.
