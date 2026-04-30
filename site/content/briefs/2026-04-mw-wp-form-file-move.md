---
title: MW WP Form WordPress Plugin Arbitrary File Move Vulnerability (CVE-2026-4347)
slug: 2026-04-mw-wp-form-file-move
description: The MW WP Form plugin for WordPress is vulnerable to arbitrary file moving due to insufficient file path validation, allowing unauthenticated attackers to move arbitrary files on the server, potentially leading to remote code execution.
date: "2026-04-02T06:16:23Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - wordpress
  - file-move
  - rce
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-4347
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4347
rules:
  - title: Detect MW WP Form Arbitrary File Move Attempt
    description: Detects potential attempts to exploit CVE-2026-4347 by monitoring for suspicious file path manipulations in requests to the MW WP Form plugin's upload handler.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect wp-config.php Access from Web Directory
    description: Detects attempts to access wp-config.php from a web-accessible directory, indicating potential exposure after a file move.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The MW WP Form plugin for WordPress is susceptible to an arbitrary file moving vulnerability identified as CVE-2026-4347. This flaw stems from a lack of proper file path validation within the 'generate_user_filepath' and 'move_temp_file_to_upload_dir' functions. All versions of the plugin up to and including 5.1.0 are affected. An unauthenticated attacker can exploit this vulnerability to move arbitrary files on the server, potentially overwriting or relocating critical system files. The most severe outcome is remote code execution, which can be achieved by moving files such as 'wp-config.php' to a location where its contents are exposed. The vulnerability is only exploitable when a file upload field exists on a form and the “Saving inquiry data in database” option is enabled, narrowing the attack surface but increasing the risk for affected installations.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site using a vulnerable version of the MW WP Form plugin (<= 5.1.0) with a file upload field enabled and the "Saving inquiry data in database" option turned on.
2.  The attacker crafts a malicious request to the WordPress site, targeting the file upload functionality of the MW WP Form plugin.
3.  The attacker manipulates the file path within the request, exploiting the insufficient validation in the 'generate_user_filepath' function to specify a target file for movement.
4.  The 'move_temp_file_to_upload_dir' function is triggered, attempting to move the uploaded file to the attacker-controlled path.
5.  Due to the lack of proper validation, the targeted file (e.g., wp-config.php) is successfully moved to a new location on the server.
6.  If wp-config.php is moved to a publicly accessible directory, the database credentials and other sensitive information become exposed.
7.  The attacker retrieves the exposed wp-config.php file, extracting database credentials and other sensitive information.
8.  Using the obtained database credentials, the attacker gains unauthorized access to the WordPress database, potentially leading to remote code execution or complete site compromise.

## Impact

Successful exploitation of CVE-2026-4347 allows unauthenticated attackers to move arbitrary files within the WordPress server's file system. This can lead to the exposure of sensitive configuration files like 'wp-config.php', leading to full database and site compromise. While the number of affected installations is currently unknown, a successful attack can have devastating consequences, including data theft, website defacement, and remote code execution. The impact is limited to sites using the vulnerable MW WP Form plugin with specific configuration settings enabled.

## Recommendation

*   Upgrade the MW WP Form plugin to the latest version (greater than 5.1.0) to patch CVE-2026-4347.
*   As a preventative measure, implement file integrity monitoring on critical files like 'wp-config.php' to detect unauthorized modifications or movement. Use file_event logs to trigger alerts.
*   Deploy the Sigma rule "Detect MW WP Form Arbitrary File Move Attempt" to identify potential exploitation attempts in web server logs.
*   Review WordPress access logs for suspicious file upload requests, focusing on requests to the MW WP Form plugin's upload handler.
