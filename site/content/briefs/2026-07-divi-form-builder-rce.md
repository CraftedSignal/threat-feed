---
brief_id: brief-2026-07-02-divi-form-builder-rce
event_id: brief-2026-07-02-divi-form-builder-rce
revision: 1
activity_at: "2026-07-02T13:41:41Z"
title: Divi Form Builder Plugin Vulnerable to Unauthenticated RCE (CVE-2026-5524)
slug: 2026-07-divi-form-builder-rce
description: The Divi Form Builder plugin for WordPress, in versions up to and including 5.1.8, is vulnerable to arbitrary file upload leading to remote code execution due to insufficient file extension validation where user-supplied input is interpolated into a regular expression, allowing unauthenticated attackers to bypass .htaccess protections with specific PHP-executable extensions and upload malicious PHP files to the /wp-content/uploads/de_fb_uploads/ directory for remote execution, particularly on Nginx-based servers where .htaccess is ineffective.
date: "2026-07-02T13:41:41Z"
lastmod: "2026-10-29T06:58:42Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:divi:form_builder_plugin_5_1_8:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-IICAICAI-CVE-2026-5524-POC&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin-vulnerability
  - rce
  - webserver
  - php
vendors:
  - Divi
products:
  - Divi Form Builder plugin <= 5.1.8 (<= 5.1.8)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers (who can obtain a nonce from any public page containing a form) to upload executable PHP files
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.006
    subtechnique_name: Python
    evidence: upload executable PHP files to the publicly accessible /wp-content/uploads/de_fb_uploads/ directory and achieve Remote Code Execution by accessing the uploaded file via HTTP.
    confidence_band: high
cves:
  - id: CVE-2026-5524
    cvss: 9.8
    epss: 0.03484
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5524
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-IICAICAI-CVE-2026-5524-POC&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-5524 Divi Form Builder Webshell Access
    description: Detects CVE-2026-5524 exploitation — HTTP GET requests to PHP-executable files in the Divi Form Builder upload directory, indicating post-exploitation webshell access.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-10-29T06:58:42Z"
    level: L2
    summary: poc_available; added CVE-2026-5524; divi form builder plugin <= 5.1.8 version <= 5.1.8
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-IICAICAI-CVE-2026-5524-POC&utm_source=rss&utm_medium=rss
---

The Divi Form Builder plugin for WordPress, impacting all versions up to and including 5.1.8, is susceptible to an Arbitrary File Upload vulnerability (CVE-2026-5524) that can lead to Remote Code Execution. This flaw stems from inadequate validation of file extensions within the `do_image_upload()` function. Attackers can leverage a critical oversight where the `acceptFileTypes` POST parameter's user-supplied input is directly interpolated into a regular expression used for file validation. This allows unauthenticated attackers to specify PHP-executable extensions like `.phtml`, `.phar`, `.php5`, or `.php7`, effectively bypassing the plugin's `.htaccess` protection, which only blocks `.php` files. The issue is further exacerbated on Nginx-based servers, where `.htaccess` files are not processed, rendering this protective measure completely ineffective. By obtaining a nonce from any public page displaying a form, threat actors can upload malicious PHP files to the `/wp-content/uploads/de_fb_uploads/` directory and execute them remotely via HTTP, gaining full control over the compromised WordPress instance.

## Attack Chain

1.  **Initial Access**: An unauthenticated attacker identifies a public WordPress page containing a Divi Form Builder form.
2.  **Information Gathering**: The attacker requests the public page via HTTP to obtain a valid nonce value from the page's source code, which is required for subsequent requests.
3.  **Exploitation Request**: The attacker crafts a malicious HTTP POST request targeting the Divi Form Builder's file upload functionality, likely to an `admin-ajax.php` endpoint with a specific action parameter.
4.  **Parameter Manipulation**: The crafted POST request includes a manipulated `acceptFileTypes` parameter, specifying a PHP-executable extension such as `.phtml`, `.php5`, `.php7`, or `.phar` to bypass the plugin's insufficient validation logic.
5.  **Malicious File Upload**: The attacker includes a PHP webshell within the POST request, which is then uploaded to the server and stored in the publicly accessible `/wp-content/uploads/de_fb_uploads/` directory.
6.  **Remote Code Execution**: The attacker accesses the newly uploaded webshell via a direct HTTP GET request to its URL (e.g., `https://example.com/wp-content/uploads/de_fb_uploads/shell.phtml`), executing arbitrary commands on the compromised server.
7.  **Post-Exploitation**: With remote code execution, the attacker can proceed with further compromise, including data exfiltration, website defacement, privilege escalation, or deploying additional malware.

## Impact

Successful exploitation of CVE-2026-5524 leads to unauthenticated Remote Code Execution on the affected WordPress site. This means attackers can execute arbitrary commands, potentially leading to complete website compromise, data theft from the underlying database, defacement of web content, or the installation of backdoors and other malicious software. For organizations, this can result in significant financial losses, reputational damage, regulatory fines due to data breaches, and a persistent foothold for further network intrusion. While specific victim counts are not available, all users of the vulnerable Divi Form Builder plugin are at risk, particularly those running on Nginx servers where `.htaccess` protections are ineffective.

## Recommendation

*   **Patch CVE-2026-5524**: Immediately update the Divi Form Builder plugin to a version greater than 5.1.8 to remediate CVE-2026-5524.
*   **Deploy Sigma Rule**: Deploy the `CVE-2026-5524-Divi-Form-Builder-Webshell-Access` Sigma rule to your webserver logs to detect post-exploitation activity.
*   **Implement Server-Side Restrictions**: For Nginx servers, ensure configurations explicitly disallow the execution of PHP files within upload directories, such as `/wp-content/uploads/de_fb_uploads/`, by default.
*   **Monitor WordPress Logs**: Enable comprehensive logging for your WordPress environment, including access to web server logs, to capture requests to plugin-specific endpoints and access attempts to suspicious files.
