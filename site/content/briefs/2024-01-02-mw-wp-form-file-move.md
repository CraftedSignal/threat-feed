---
title: MW WP Form WordPress Plugin Arbitrary File Move/Read Vulnerability (CVE-2026-5436)
slug: 2024-01-02-mw-wp-form-file-move
description: The MW WP Form plugin for WordPress is vulnerable to arbitrary file move/read (CVE-2026-5436) due to insufficient validation of the $name parameter, allowing unauthenticated attackers to move arbitrary files, potentially leading to remote code execution.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - file-move
  - rce
vendors:
  - MW WP Form
products:
  - MW WP Form plugin
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5436
    cvss: 8.1
    epss: 0.01069
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5436
rules:
  - title: Detect MW WP Form Arbitrary File Move Attempt via POST Request
    description: Detects potential attempts to exploit the MW WP Form arbitrary file move vulnerability by monitoring HTTP POST requests containing the mwf_upload_files parameter.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect wp-config.php File Move via Rename Function
    description: Detects potential file moves/renames targeting wp-config.php
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The MW WP Form plugin for WordPress, versions up to and including 5.1.1, contains an arbitrary file move/read vulnerability (CVE-2026-5436). This vulnerability stems from insufficient validation of the `$name` parameter (upload field key) passed to the `generate_user_file_dirpath()` function. The `path_join()` function returns absolute paths unchanged, bypassing intended base directory restrictions. An attacker-controlled key is injected via the `mwf_upload_files[]` POST parameter, which is then loaded into the plugin's Data model via `_set_request_valiables()`. Successful exploitation requires a file upload field to be present on the form and the “Saving inquiry data in database” option to be enabled. This vulnerability allows unauthenticated attackers to move sensitive files, such as `wp-config.php`, potentially leading to remote code execution.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious HTTP POST request targeting a WordPress site with the vulnerable MW WP Form plugin installed.
2.  The attacker includes a `mwf_upload_files[]` POST parameter containing a crafted key (the `$name` parameter). This key will be used as the filename for the uploaded file.
3.  The `_set_request_valiables()` function within the plugin loads the attacker-supplied key into the plugin's Data model.
4.  During form processing, `regenerate_upload_file_keys()` iterates over the uploaded file keys.
5.  For each key, `generate_user_filepath()` is called, passing the attacker-supplied key as the `$name` argument.
6.  The `$name` argument is passed to the `path_join()` function, which incorrectly handles absolute paths.
7.  The _get_attachments() method then passes the resolved file path to move_temp_file_to_upload_dir(), which calls rename() to move the targeted file.
8.  The attacker leverages the ability to move arbitrary files to overwrite or relocate critical system files (e.g., `wp-config.php`), ultimately achieving remote code execution.

## Impact

Successful exploitation allows unauthenticated attackers to move arbitrary files on the server hosting the WordPress site. This can lead to sensitive information disclosure by moving files to a publicly accessible directory or, more critically, remote code execution by moving configuration files like `wp-config.php`, which contains database credentials and other sensitive information. The impact is critical, potentially leading to full server compromise. The number of affected sites depends on the adoption rate of the vulnerable plugin version.

## Recommendation

*   Deploy the Sigma rule "Detect MW WP Form Arbitrary File Move Attempt via POST Request" to your SIEM to detect exploitation attempts by monitoring HTTP POST requests to the WordPress site (log source: webserver).
*   Apply the available patch or upgrade the MW WP Form plugin to a version greater than 5.1.1 to remediate CVE-2026-5436.
*   Enable web server logging with detailed request information to capture the `mwf_upload_files[]` POST parameter for forensic analysis (log source: webserver).
*   Monitor file system events for unexpected file movements, specifically targeting configuration files such as `wp-config.php` (log source: file_event).
