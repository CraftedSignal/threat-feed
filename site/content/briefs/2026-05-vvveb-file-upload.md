---
title: Vvveb Unrestricted File Upload Vulnerability (CVE-2026-41937)
slug: 2026-05-vvveb-file-upload
description: Vvveb before 1.0.8.3 is vulnerable to unrestricted file upload, allowing super_admin users to execute arbitrary PHP code by uploading a malicious plugin ZIP file containing PHP code which is then accessible via HTTP requests.
date: "2026-05-14T15:17:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - file upload
  - remote code execution
  - web application
vendors:
  - Vvveb
products:
  - Vvveb
  - Vvveb < 1.0.8.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41937
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41937
  - https://github.com/givanz/Vvveb/commit/04f0294350ec429e307cd31c2e777a4797c868d6
  - https://github.com/givanz/Vvveb/releases/tag/1.0.8.3
  - https://www.vulncheck.com/advisories/vvveb-unrestricted-file-upload-rce-via-plugin-upload
rules:
  - title: Detect CVE-2026-41937 Exploitation Attempt — Vvveb Plugin Upload
    description: Detects CVE-2026-41937 exploitation — an attempt to upload a malicious plugin in Vvveb containing PHP code in public/index.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Vvveb public/index.php Access
    description: Detects access to public/index.php within Vvveb plugins directory, which could indicate exploitation of CVE-2026-41937 after malicious file upload.
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

Vvveb is vulnerable to an unrestricted file upload vulnerability (CVE-2026-41937) affecting versions prior to 1.0.8.3. The vulnerability exists in the plugin upload endpoint, allowing super_admin users to upload arbitrary files. An attacker can exploit this by crafting a malicious plugin ZIP file containing a `plugin.php` file with a valid `Slug` header, alongside a `public/index.php` file containing arbitrary PHP code. Upon uploading this malicious plugin, the PHP code within `public/index.php` becomes accessible via unauthenticated HTTP requests to the plugin's public path, resulting in remote code execution (RCE) as the web server user.

## Attack Chain

1. An attacker identifies a Vvveb instance running a version prior to 1.0.8.3.
2. The attacker authenticates as a `super_admin` user.
3. The attacker crafts a malicious ZIP archive containing two files: `plugin.php` and `public/index.php`.
4. The `plugin.php` file includes a valid `Slug` header to bypass initial checks.
5. The `public/index.php` file contains arbitrary PHP code intended for execution.
6. The attacker uploads the crafted ZIP file through the plugin upload endpoint.
7. The Vvveb application extracts the ZIP file, placing the `public/index.php` in a publicly accessible directory.
8. The attacker sends an unauthenticated HTTP request to the `public/index.php` file's URL, triggering the execution of the embedded PHP code on the server.

## Impact

Successful exploitation of this vulnerability leads to arbitrary PHP code execution on the Vvveb server. This allows an attacker with `super_admin` privileges to gain complete control of the affected Vvveb instance, potentially leading to data breaches, defacement, or further lateral movement within the network. Due to the unrestricted nature of the file upload, attackers can deploy backdoors, execute system commands, and compromise the confidentiality, integrity, and availability of the application and underlying system.

## Recommendation

*   Upgrade Vvveb to version 1.0.8.3 or later to patch CVE-2026-41937.
*   Implement the Sigma rule "Detect CVE-2026-41937 Exploitation Attempt — Vvveb Plugin Upload" to detect malicious plugin uploads based on HTTP request characteristics.
*   Restrict access to the plugin upload endpoint to authorized personnel only.
*   Monitor web server logs for suspicious activity, particularly requests to newly uploaded PHP files.
