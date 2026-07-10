---
title: DSGVO Google Web Fonts GDPR WordPress Plugin Arbitrary File Upload Vulnerability (CVE-2026-3535)
slug: 2024-01-29-wordpress-plugin-upload
description: The DSGVO Google Web Fonts GDPR plugin for WordPress is vulnerable to unauthenticated arbitrary file upload due to missing file type validation, allowing attackers to upload PHP webshells and achieve remote code execution.
date: "2024-01-29T12:00:00Z"
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
  - CVE-2026-3535
products:
  - DSGVO Google Web Fonts GDPR plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-3535
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3535
rules:
  - title: Detect WordPress Plugin Arbitrary File Upload Attempt
    description: Detects attempts to exploit the DSGVO Google Web Fonts GDPR plugin arbitrary file upload vulnerability (CVE-2026-3535) by monitoring requests to download files via the vulnerable function.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Webshell Upload via DSGVO Google Web Fonts GDPR Plugin
    description: Detects the writing of php files to the uploads directory, indicative of a webshell upload attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
    techniques:
      - T1189
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The DSGVO Google Web Fonts GDPR plugin for WordPress is vulnerable to arbitrary file upload due to a flaw in the `DSGVOGWPdownloadGoogleFonts()` function. This vulnerability, identified as CVE-2026-3535, affects all versions of the plugin up to and including 1.1. The vulnerable function lacks file type validation and is accessible without authentication via a `wp_ajax_nopriv_` hook. An unauthenticated attacker can exploit this by submitting a URL that points to a CSS file. The plugin then extracts URLs from the CSS file's content and downloads those files to a publicly accessible directory on the WordPress server. The absence of file type validation allows the attacker to upload arbitrary files, including PHP webshells, leading to remote code execution. The exploit is limited to sites using specific themes, including twentyfifteen, twentyseventeen, twentysixteen, storefront, salient, or shapely.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using a vulnerable theme and the vulnerable plugin.
2. The attacker crafts a malicious CSS file hosted on a server they control. This CSS file contains URLs pointing to a PHP webshell.
3. The attacker sends a request to the WordPress site's `wp-admin/admin-ajax.php` endpoint, triggering the `wp_ajax_nopriv_DSGVOGWPdownloadGoogleFonts` action. The request includes a parameter pointing to the malicious CSS file.
4. The `DSGVOGWPdownloadGoogleFonts()` function fetches the attacker-controlled CSS file.
5. The function parses the CSS file and extracts the URLs, including the URL pointing to the PHP webshell.
6. The function downloads the PHP webshell to a publicly accessible directory within the WordPress installation, such as `/wp-content/uploads/`. Because of the missing validation, the PHP file is saved.
7. The attacker accesses the uploaded PHP webshell via a direct HTTP request to the file's location.
8. The attacker executes arbitrary commands on the server via the PHP webshell, gaining control of the WordPress site and potentially the underlying server.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to upload arbitrary files, including PHP webshells, onto vulnerable WordPress installations. This leads to remote code execution, potentially granting the attacker complete control over the affected web server. The attacker can then steal sensitive data, deface the website, install malware, or use the compromised server as a launching point for further attacks. Given the widespread use of WordPress, a large number of websites are potentially vulnerable.

## Recommendation

*   Upgrade the DSGVO Google Web Fonts GDPR plugin to a version patched against CVE-2026-3535 to remediate the vulnerability.
*   Implement the Sigma rule `Detect WordPress Plugin Arbitrary File Upload Attempt` to detect attempts to exploit this vulnerability by monitoring for requests to download files via the vulnerable function.
*   Monitor web server logs for access to unusual files within the `/wp-content/uploads/` directory, especially PHP files, as indicators of successful exploitation.
*   Implement the Sigma rule `Detect PHP Webshell Upload via DSGVO Google Web Fonts GDPR Plugin` to detect the writing of php files to the uploads directory.
*   Consider using a Web Application Firewall (WAF) to block requests targeting the `wp_ajax_nopriv_DSGVOGWPdownloadGoogleFonts` action.
