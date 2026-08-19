---
title: Arbitrary File Deletion in Atarim AI Agency for WordPress Plugin
slug: 2026-08-atarim-wordpress-file-deletion
description: The Atarim - AI Agency for WordPress plugin is vulnerable to arbitrary file deletion via directory traversal, enabling attackers with author-level access to delete sensitive files and potentially achieve remote code execution.
date: "2026-08-19T06:58:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - directory-traversal
  - cve-2026-19942
vendors:
  - Atarim
products:
  - Atarim – AI Agency for WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for authenticated attackers, with author-level access and above, to delete arbitrary files on the server
    confidence_band: high
cves:
  - id: CVE-2026-19942
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19942
rules:
  - title: Detects CVE-2026-19942 Exploitation - Arbitrary File Deletion Attempt
    description: Detects exploitation attempts against CVE-2026-19942 by identifying directory traversal payloads within the Atarim plugin API request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The Atarim - AI Agency for WordPress plugin (versions 5.1.1 and below) contains a critical vulnerability due to insufficient file path validation within the `AVCF_Abilities_Media::register` function. This flaw, identified as CVE-2026-19942, allows authenticated attackers with author-level permissions or higher to perform arbitrary file deletion on the hosting server. By leveraging directory traversal techniques through the `atarim/update-post-field` ability, an attacker can manipulate the `_wp_attached_file` metadata of an attachment they control. Subsequent invocation of the `atarim/replace-media-file` function forces the server to resolve the manipulated path and execute an `unlink()` operation on the targeted file. Deleting critical system files such as `wp-config.php` may cause the application to revert to an unconfigured state, facilitating further exploitation or remote code execution.

## Attack Chain

1. Attacker authenticates to the target WordPress site with an account possessing at least author-level privileges.
2. Attacker performs a media upload or selects an existing attachment owned by their user account.
3. Attacker sends a request to the `atarim/update-post-field` endpoint to modify the `_wp_attached_file` metadata for the attachment.
4. The attacker includes a directory traversal payload (e.g., `../../../../wp-config.php`) within the metadata field.
5. Attacker invokes the `atarim/replace-media-file` action via the plugin's REST API or callback mechanism.
6. The `execute_callback` function triggers `get_attached_file()` using the manipulated metadata path.
7. The application executes `unlink()` on the resolved path, resulting in the permanent deletion of the targeted system file from the disk.
8. Attacker leverages the deleted file state (e.g., re-running the WordPress installer due to a missing configuration) to gain unauthorized control or RCE.

## Impact

Successful exploitation allows for the deletion of critical WordPress configuration and core files. In the context of a WordPress environment, the removal of `wp-config.php` forces the site into an initial setup state, enabling an attacker to re-initialize the database connection to an attacker-controlled instance or perform unauthorized administrative actions. This vulnerability impacts any WordPress site running Atarim AI Agency for WordPress version 5.1.1 or lower.

## Recommendation

* Immediately update the Atarim - AI Agency for WordPress plugin to a patched version (5.1.2 or later).
* Review administrative and author-level user accounts for recent anomalous activity or unauthorized file manipulation requests.
* Monitor web server logs for suspicious `POST` requests to `atarim/update-post-field` or `atarim/replace-media-file` endpoints that contain directory traversal patterns (e.g., `../`).
* Implement file integrity monitoring (FIM) on critical application files, specifically `wp-config.php`, to alert on unexpected deletion events.
