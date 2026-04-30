---
title: Perfmatters WordPress Plugin Arbitrary File Deletion Vulnerability (CVE-2026-4350)
slug: 2026-04-perfmatters-file-deletion
description: The Perfmatters plugin for WordPress versions up to 2.5.9.1 is vulnerable to arbitrary file deletion via path traversal, allowing authenticated attackers with minimal privileges to delete sensitive files.
date: "2026-04-03T08:16:17Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4350
  - wordpress
  - perfmatters
  - file-deletion
  - path-traversal
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-4350
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4350
rules:
  - title: Detect Perfmatters Arbitrary File Deletion Attempt
    description: Detects potential attempts to exploit the Perfmatters arbitrary file deletion vulnerability (CVE-2026-4350) through path traversal sequences in the URI query.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect Perfmatters Arbitrary File Deletion Attempt POST
    description: Detects potential attempts to exploit the Perfmatters arbitrary file deletion vulnerability (CVE-2026-4350) through path traversal sequences in the URI query using POST method.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Perfmatters plugin, a popular WordPress performance optimization tool, contains a critical vulnerability (CVE-2026-4350) affecting versions up to and including 2.5.9.1. This flaw enables authenticated attackers with Subscriber-level access, the lowest privilege level in WordPress, to delete arbitrary files on the server. The vulnerability stems from the `PMCS::action_handler()` method's failure to sanitize the `$_GET['delete']` parameter. This lack of validation allows for path traversal attacks using sequences like `../`, enabling attackers to navigate outside the intended storage directory and delete any accessible file. Successful exploitation can lead to the deletion of critical files such as `wp-config.php`, effectively disabling the website and potentially allowing a full site takeover.

## Attack Chain

1. Attacker identifies a WordPress site using a vulnerable version (<=2.5.9.1) of the Perfmatters plugin.
2. Attacker gains Subscriber-level access to the WordPress site. This can be achieved through registration or compromised credentials.
3. Attacker crafts a malicious HTTP GET request targeting the WordPress site. The request includes the `delete` parameter with a path traversal payload. For example: `?delete=../../../../wp-config.php`.
4. The request is sent to the `PMCS::action_handler()` method within the Perfmatters plugin.
5. The `PMCS::action_handler()` method processes the unsanitized `$_GET['delete']` parameter.
6. The plugin concatenates the malicious path with the storage directory.
7. The `unlink()` function executes, deleting the file specified by the attacker's path traversal payload.
8. If the attacker successfully deletes `wp-config.php`, the WordPress site becomes inaccessible and redirects to the installation wizard, potentially allowing for complete site takeover.

## Impact

Successful exploitation of CVE-2026-4350 allows attackers to delete arbitrary files on a vulnerable WordPress server. A key target is `wp-config.php`, which contains sensitive database credentials. Deleting this file forces WordPress into the installation wizard, potentially leading to a full site takeover. The impact ranges from defacement and data loss to complete control of the website, impacting businesses, organizations, and individuals relying on WordPress for their online presence. The ease of exploitation due to the low privilege requirements makes this a high-risk vulnerability.

## Recommendation

*   Immediately update the Perfmatters plugin to the latest version to patch CVE-2026-4350.
*   Implement the provided Sigma rule `Detect Perfmatters Arbitrary File Deletion Attempt` to identify potential exploitation attempts based on `cs-uri-query` in web server logs.
*   Consider implementing rate limiting on requests to `wp-admin/options.php` to mitigate potential brute-force exploitation attempts targeting this vulnerability.
*   Review web server access logs for unusual patterns in `cs-uri-query` parameters containing `../` sequences, as these may indicate path traversal attempts.
