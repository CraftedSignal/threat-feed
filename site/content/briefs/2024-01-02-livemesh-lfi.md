---
title: Livemesh Addons for Elementor Plugin LFI Vulnerability (CVE-2026-1620)
slug: 2024-01-02-livemesh-lfi
description: The Livemesh Addons for Elementor plugin for WordPress is vulnerable to Local File Inclusion (LFI) due to insufficient sanitization of the template name parameter, allowing authenticated attackers to include and execute arbitrary files on the server.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - lfi
  - cve-2026-1620
  - elementor
vendors:
  - Livemesh
products:
  - Livemesh Addons for Elementor
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-1620
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1620
rules:
  - title: Detect Livemesh Elementor LFI via Directory Traversal
    description: Detects attempts to exploit the Livemesh Addons for Elementor LFI vulnerability by identifying directory traversal sequences in the request URI.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect Livemesh Elementor LFI via wp-config.php Access
    description: Detects attempts to exploit the Livemesh Addons for Elementor LFI vulnerability by identifying directory traversal sequences in the request URI, specifically targeting wp-config.php.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Livemesh Addons for Elementor plugin, a popular WordPress extension, is susceptible to a Local File Inclusion (LFI) vulnerability, identified as CVE-2026-1620. This flaw exists in all versions up to and including version 9.0. The root cause lies in the inadequate sanitization of the `template name` parameter within the `lae_get_template_part()` function. The plugin uses a weak `str_replace()` approach that can be circumvented using recursive directory traversal sequences (e.g., `../../`). This vulnerability allows authenticated attackers with Contributor-level access or higher to include and potentially execute arbitrary files residing on the server, posing a significant risk to the WordPress installation. The attacker needs to either convince an administrator to perform a specific action or to install the Elementor plugin.

## Attack Chain

1.  Attacker gains Contributor-level or higher access to the WordPress instance, either through credential compromise or registration (if enabled).
2.  Attacker crafts a malicious HTTP request targeting the vulnerable `lae_get_template_part()` function. This request includes a `template name` parameter containing a payload with directory traversal sequences (e.g., `../../../../etc/passwd`).
3.  The vulnerable `lae_get_template_part()` function attempts to sanitize the input using `str_replace()`, which is insufficient to prevent directory traversal.
4.  The function uses the manipulated `template name` parameter to include a file from the server's file system.
5.  If the included file is a PHP file, the server executes the code within the file.
6.  The attacker leverages the ability to include arbitrary files to read sensitive information, such as WordPress configuration files (e.g., `wp-config.php`) containing database credentials.
7.  The attacker further escalates the attack by including files that enable remote code execution, such as log files or session files where they can inject malicious PHP code.
8.  The attacker achieves arbitrary code execution on the server, allowing them to install backdoors, deface the website, or steal sensitive data.

## Impact

Successful exploitation of this LFI vulnerability (CVE-2026-1620) could allow attackers to gain unauthorized access to sensitive information, including database credentials and configuration files. An attacker could read arbitrary files on the server leading to full system compromise. Since this is a popular plugin, a successful widespread attack could impact thousands of WordPress sites across various sectors.

## Recommendation

*   Upgrade the Livemesh Addons for Elementor plugin to a version greater than 9.0 to patch CVE-2026-1620.
*   Implement a Web Application Firewall (WAF) rule to detect and block requests containing directory traversal sequences in the `template name` parameter targeting the `lae_get_template_part()` function.
*   Deploy the provided Sigma rule to your SIEM to detect exploitation attempts by monitoring web server logs for directory traversal patterns in the request URI.
*   Review user access and permissions within the WordPress environment, ensuring that users are granted only the necessary privileges to minimize the impact of potential account compromise.
