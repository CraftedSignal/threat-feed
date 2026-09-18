---
title: Arbitrary File Upload Vulnerability in WP Cloud Plugins for WordPress
slug: 2026-09-wp-cloud-plugins-rce
description: Multiple WP Cloud Plugins for WordPress are vulnerable to arbitrary file upload via the download_file_to_uploads function, enabling remote code execution by authenticated attackers.
date: "2026-09-18T22:11:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - wordpress
  - cve-2026-93031
  - rce
vendors:
  - WP Cloud Plugins
products:
  - Use-your-Drive (2.0 - 3.8.3)
  - Out-of-the-Box (2.0 - 3.8.3)
  - Share-one-Drive (2.0 - 3.8.3)
  - Lets-Box (2.0 - 3.8.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for authenticated attackers, with subscriber-level access and above, to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-93031
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93031
rules:
  - title: Detects CVE-2026-93031 Exploitation - PHP Upload to Plugin Directory
    description: Detects attempts to upload executable PHP files via the vulnerable plugin download actions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade affected WP Cloud Plugins to versions beyond 3.8.3.
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists in versions up to and including 3.8.3.
  mitigation_plan:
    - priority: immediate
      action: Patch plugin suite to latest version.
      owner: IT Operations
      addresses: CVE-2026-93031
      evidence: NVD vulnerability disclosure.
---

The WP Cloud Plugins suite - including Use-your-Drive, Out-of-the-Box, Share-one-Drive, and Lets-Box - contains an arbitrary file upload vulnerability affecting versions 2.0 through 3.8.3. The flaw resides within the `download_file_to_uploads` function. Due to the improper registration of the import action via `wp_ajax_nopriv_` and a missing capability check in the `can_import()` function, the plugin fails to restrict file uploads to authorized users. Furthermore, the plugin does not validate file extensions or contents against `get_allowed_mime_types()` before writing files to the server's uploads directory. This allows authenticated attackers with subscriber-level access or higher to upload malicious, executable files to the web server, which can subsequently be triggered to achieve remote code execution (RCE). This vulnerability poses a significant risk to the integrity and confidentiality of affected WordPress installations.

## Attack Chain

1. Attacker identifies a WordPress site utilizing vulnerable versions of Use-your-Drive, Out-of-the-Box, Share-one-Drive, or Lets-Box.
2. Attacker obtains subscriber-level access (or leverages the unauthenticated `wp_ajax_nopriv_` exposure) to interact with the plugin's API.
3. Attacker crafts a malicious request targeting the `download_file_to_uploads` function, bypassing the missing `can_import()` capability check.
4. Attacker provides a remote path to a malicious payload (e.g., a PHP webshell) within the request parameters.
5. The plugin downloads the file from the remote source without validating against `get_allowed_mime_types()`.
6. The file is written to the WordPress `uploads` directory with an executable extension.
7. Attacker navigates directly to the uploaded file path via the web browser to trigger code execution.
8. Attacker achieves remote code execution to perform system-level operations or data exfiltration.

## Impact

Successful exploitation allows for full remote code execution on the underlying web server hosting the WordPress site. This can lead to total site compromise, including the theft of database credentials, defacement, or the installation of persistent backdoors. Affected sectors include any organization hosting WordPress instances with the vulnerable suite of plugins.

## Recommendation

1. Upgrade Use-your-Drive, Out-of-the-Box, Share-one-Drive, and Lets-Box to versions beyond 3.8.3 immediately.
2. Monitor web server logs for HTTP requests directed to the plugin's API endpoints that result in the creation of executable files (e.g., .php files) within the WordPress `uploads` directory.
3. Implement strict file upload directory permissions to prevent the execution of scripts in folders where user-supplied content is stored.
4. Audit WordPress user accounts to ensure unauthorized subscriber-level accounts have not been created or used to facilitate this exploitation.
