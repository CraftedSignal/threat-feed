---
title: Geeky Bot WordPress Plugin Missing Authorization Vulnerability Leads to Remote Code Execution
slug: 2024-01-wordpress-geekybot-rce
description: The Geeky Bot plugin for WordPress is vulnerable to Missing Authorization in versions up to 1.2.2, allowing unauthenticated attackers to perform arbitrary plugin installation and achieve remote code execution by exploiting a nopriv AJAX route and uploading malicious ZIP files.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - rce
  - missing-authorization
  - cve-2026-5294
  - code-execution
vendors:
  - WordPress
products:
  - Geeky Bot plugin for WordPress <= 1.2.2
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1105
    technique_name: Remote File Copy
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2026-5294
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5294
rules:
  - title: Detect Suspicious WordPress Plugin Installation via AJAX
    description: Detects potential exploitation of the Geeky Bot plugin vulnerability by monitoring for suspicious POST requests to admin-ajax.php indicative of plugin installation attempts.
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
  - title: Detect Unauthorized Plugin Installation in WordPress
    description: Detects unauthorized plugin installations by monitoring file creation events in the wp-content/plugins/ directory.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Geeky Bot plugin for WordPress, in versions up to and including 1.2.2, contains a critical missing authorization vulnerability. This flaw stems from a publicly accessible (nopriv) AJAX route that lacks proper access controls. Attackers can leverage this route to control model and function dispatch, ultimately reaching a plugin installer helper function. This function allows the download and extraction of attacker-supplied ZIP files directly into the wp-content/plugins/ directory. By uploading a malicious plugin in a ZIP archive, an unauthenticated attacker can achieve remote code execution on the target WordPress server. This vulnerability poses a significant risk to WordPress sites using the Geeky Bot plugin.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site running a vulnerable version of the Geeky Bot plugin (<= 1.2.2).
2.  The attacker crafts a malicious ZIP archive containing a PHP file with arbitrary code.
3.  The attacker sends a crafted HTTP POST request to the vulnerable nopriv AJAX endpoint (e.g., `/wp-admin/admin-ajax.php`) specifying the model/function to trigger the plugin installation helper.
4.  The request includes a URL pointing to the attacker's malicious ZIP archive.
5.  The WordPress server downloads the ZIP archive from the attacker-controlled URL.
6.  The server extracts the contents of the ZIP archive into the `wp-content/plugins/` directory.
7.  The attacker accesses the uploaded PHP file through a web browser (e.g., `/wp-content/plugins/malicious-plugin/shell.php`).
8.  The server executes the attacker's code, granting the attacker arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to gain complete control of the affected WordPress website. This can lead to data breaches, website defacement, malware distribution, and further compromise of the underlying server infrastructure. Given the widespread use of WordPress and the simplicity of the exploit, numerous websites are potentially at risk. The CVSS v3.1 base score of 9.8 indicates the criticality of this vulnerability.

## Recommendation

*   Immediately remove the Geeky Bot plugin from all WordPress installations.
*   Monitor web server logs for suspicious POST requests to `/wp-admin/admin-ajax.php` with parameters indicative of plugin installation attempts, which can be detected by the Sigma rule "Detect Suspicious WordPress Plugin Installation via AJAX".
*   Implement file integrity monitoring on the `wp-content/plugins/` directory to detect unauthorized file creation or modification, triggering on events matched by the "Detect Unauthorized Plugin Installation in WordPress" Sigma rule.
*   Apply principle of least privilege to the web server user to limit the impact of potential code execution.
