---
title: wpForo Forum Plugin Arbitrary File Deletion Vulnerability (CVE-2026-5809)
slug: 2026-04-wpforo-file-deletion
description: The wpForo Forum plugin for WordPress is vulnerable to arbitrary file deletion due to a logic flaw that allows authenticated users to delete arbitrary files writable by the PHP process by manipulating post metadata.
date: "2026-04-11T08:16:05Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - wordpress
  - file-deletion
  - plugin
  - CVE-2026-5809
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-5809
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5809
rules:
  - title: Detect wpForo Arbitrary File Deletion Attempt
    description: Detects attempts to exploit the wpForo arbitrary file deletion vulnerability by monitoring for POST requests containing the wpftcf_delete parameter and suspicious file paths.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect wpForo Malicious File Path in Post Meta
    description: Detects attempts to inject malicious file paths into wpForo post meta data via the data[body][fileurl] parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The wpForo Forum plugin, a popular WordPress plugin, is susceptible to an arbitrary file deletion vulnerability (CVE-2026-5809) affecting versions up to and including 3.0.2. The vulnerability stems from insufficient validation of user-supplied data within the `topic_add()` and `topic_edit()` action handlers. Specifically, the plugin improperly handles array values in the `$_REQUEST` data, storing them as postmeta without proper filtering. An authenticated attacker (subscriber-level or higher) can exploit this by injecting a malicious file path into the `data[body][fileurl]` parameter. This injected path is subsequently used in a file deletion function without adequate sanitization, leading to potential deletion of critical system files. This vulnerability allows attackers to potentially cripple the WordPress installation or gain further access to the server.

## Attack Chain

1.  An attacker authenticates to the WordPress site with at least subscriber-level privileges.
2.  The attacker crafts a malicious HTTP request targeting the `topic_add()` or `topic_edit()` action handler.
3.  Within the request, the attacker includes the `data[body][fileurl]` parameter containing the path to the file they wish to delete (e.g., `/var/www/html/wp-config.php`).
4.  The wpForo plugin stores the attacker-supplied `fileurl` value as postmeta associated with the forum topic without proper validation.
5.  The attacker crafts another request, this time including the `wpftcf_delete[]=body` parameter, targeting the `topic_edit` action.
6.  The `add_file()` method retrieves the poisoned `fileurl` from the stored postmeta record.
7.  The plugin attempts to sanitize the path using `wpforo_fix_upload_dir()`, but this function only modifies paths within the legitimate wpForo upload directory, leaving other paths untouched.
8.  The plugin calls `wp_delete_file()` on the unsanitized path, resulting in the deletion of the targeted file if the PHP process has write permissions.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to delete arbitrary files on the server, provided the PHP process has the necessary write permissions. This can lead to a denial of service by deleting core WordPress files or configuration files such as `wp-config.php`. The CVSS v3.1 base score for this vulnerability is 7.1, indicating a high severity. This could lead to complete compromise of the WordPress installation and potential further exploitation of the server.

## Recommendation

*   Upgrade the wpForo Forum plugin to a version higher than 3.0.2 to patch CVE-2026-5809.
*   Deploy the Sigma rule "Detect wpForo Arbitrary File Deletion Attempt" to your SIEM to detect potential exploitation attempts by monitoring HTTP requests to WordPress.
*   Implement stricter file permission controls to limit the PHP process's write access to only necessary directories and files.
*   Monitor web server logs for suspicious POST requests containing the `wpftcf_delete` parameter, as highlighted in the Attack Chain.
