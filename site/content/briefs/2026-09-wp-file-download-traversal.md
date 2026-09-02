---
title: Arbitrary File Deletion in WP File Download Plugin
slug: 2026-09-wp-file-download-traversal
description: The WP File Download plugin for WordPress contains a path traversal vulnerability in its file save and delete functions, allowing authenticated subscribers to delete arbitrary files on the server, potentially leading to remote code execution.
date: "2026-09-02T05:11:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:wp_file_download:*:*:*:*:*:*:*:*
vendors:
  - WordPress
products:
  - WP File Download (all versions)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The vulnerability makes it possible for authenticated attackers to delete arbitrary files, leading to remote code execution.
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The WP File Download plugin is vulnerable to arbitrary file deletion.
    confidence_band: high
cves:
  - id: CVE-2026-14982
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14982
rules:
  - title: Detect CVE-2026-14982 Exploitation - Arbitrary File Deletion Attempt
    description: Detects exploitation attempts against the WP File Download plugin where attackers POST to file management endpoints with path traversal indicators.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor web server logs for traversal sequences in task-based requests
      owner: Detection Engineering
      due: 24h
  mitigation_plan:
    - priority: immediate
      action: Disable the WP File Download plugin until a vendor-validated update is released
      owner: IT Operations
      addresses: CVE-2026-14982
---

The WP File Download plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient input validation in its file management functions. An authenticated attacker with subscriber-level access can exploit this flaw to delete files outside the intended directories, including critical WordPress configuration files such as wp-config.php. The vulnerability persists across all plugin versions, highlighting a lack of capability checks and nonce enforcement in the 'file.save' and 'file.delete' AJAX endpoints. Successful exploitation could allow an attacker to delete the wp-config.php file, triggering a re-installation process that may lead to site compromise or complete remote code execution. Defenders should prioritize auditing web server access logs for anomalous POST requests directed at these specific plugin endpoints.

## Attack Chain

1. Attacker authenticates as a user with at least subscriber-level privileges on the WordPress site.
2. Attacker crafts an HTTP POST request targeting the plugin's 'file.save' endpoint.
3. The request includes a path traversal payload within the file metadata or path parameter.
4. The plugin application fails to sanitize the input, persisting the malicious path string into the plugin's internal database/metadata store.
5. Attacker sends a second HTTP POST request targeting the 'file.delete' endpoint.
6. The application retrieves the malicious metadata and passes the path-traversed string to an unvalidated 'unlink' system call.
7. The system deletes the specified sensitive file, such as 'wp-config.php'.
8. The application is rendered in an uninitialized state, allowing the attacker to re-configure the WordPress instance or achieve full system compromise.

## Impact

Successful exploitation results in the permanent loss of arbitrary files on the server hosting the WordPress installation. In the context of WordPress, the deletion of 'wp-config.php' forces the application to revert to its initial setup state, facilitating remote code execution or complete takeover of the web application by unauthorized parties.

## Recommendation

Prioritize the immediate removal or disabling of the WP File Download plugin until a vendor patch is applied to enforce capability and nonce validation. Monitor web server logs for high-frequency or unauthorized POST requests to 'admin-ajax.php' involving 'file.save' and 'file.delete' tasks.
