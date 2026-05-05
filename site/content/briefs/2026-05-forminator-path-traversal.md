---
title: Forminator Forms Plugin Path Traversal Vulnerability
slug: 2026-05-forminator-path-traversal
description: The Forminator Forms WordPress plugin is vulnerable to an unauthenticated path traversal that allows reading arbitrary files on the server when specific features are enabled.
date: "2026-05-05T07:16:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - wordpress
  - plugin
vendors:
  - WordPress
products:
  - Forminator Forms – Contact Form, Payment Form & Custom Form Builder plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5192
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5192
rules:
  - title: Detect Forminator Path Traversal Attempt
    description: Detects path traversal attempts in the 'upload-1[file][file_path]' parameter of the Forminator plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Arbitrary File Access via Forminator Path Traversal
    description: Detects web server access to sensitive files (e.g., wp-config.php) potentially triggered by the Forminator path traversal vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Forminator Forms plugin for WordPress, a widely used plugin for creating contact forms and payment forms, contains a path traversal vulnerability (CVE-2026-5192) affecting versions up to and including 1.52.1. This flaw enables unauthenticated attackers to potentially read sensitive files from the underlying server. Successful exploitation hinges on a confluence of factors: the existence of a publicly accessible form incorporating a File Upload field, the activation of "Save and Continue" functionality within the form's behavior settings, and the configuration of email notifications to include uploaded files as attachments. This vulnerability poses a significant risk, as exposed files could contain configuration details, database credentials, or other sensitive information.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using a vulnerable version of the Forminator plugin (<= 1.52.1).
2. The attacker discovers or locates a publicly accessible form with a File Upload field.
3. The form has "Save and Continue" enabled within its Behavior settings.
4. The "Save and Continue" email notification is configured to attach uploaded files in Email Notifications.
5. The attacker crafts a malicious request to the 'upload-1[file][file_path]' parameter with a path traversal payload (e.g., '../../../../wp-config.php').
6. The server processes the request and attempts to access the file specified in the manipulated path.
7. Due to insufficient input validation, the server reads the arbitrary file.
8. The attacker retrieves the file content from the server's response or via the attached file in the email notification. This allows the attacker to access sensitive data such as wp-config.php.

## Impact

Successful exploitation of this path traversal vulnerability could allow attackers to read arbitrary files on the WordPress server. This could expose sensitive information, such as database credentials stored in `wp-config.php`, potentially leading to full compromise of the WordPress site and the underlying server. The number of affected sites is potentially very high given the popularity of the Forminator plugin. This can lead to data breaches, financial losses, and reputational damage.

## Recommendation

*   Upgrade the Forminator Forms plugin to the latest version to patch CVE-2026-5192.
*   Inspect publicly accessible forms for File Upload fields and disable "Save and Continue" functionality or email attachment of uploaded files as a temporary mitigation.
*   Deploy the Sigma rule `Detect Forminator Path Traversal Attempt` to your SIEM to identify exploitation attempts.
*   Monitor web server logs for requests containing path traversal sequences (e.g., `../`) in the `upload-1[file][file_path]` parameter.
*   Implement strict input validation and sanitization on file paths to prevent path traversal vulnerabilities in other web applications.
