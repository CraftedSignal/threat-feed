---
title: Arbitrary File Deletion in Nex Forms Plugin for WordPress
slug: 2026-08-nex-forms-traversal
description: The Nex Forms - Ultimate Form Builder - Lite plugin for WordPress is vulnerable to arbitrary file deletion via path traversal, allowing authenticated attackers to delete critical system files.
date: "2026-08-01T09:50:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - arbitrary-file-deletion
  - path-traversal
  - web-application
vendors:
  - WordPress
products:
  - Nex Forms – Ultimate Form Builder – Lite (<= 9.2.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This makes it possible for authenticated attackers, with admin-level access and above, to delete arbitrary files on the affected site's server, including wp-config.
    confidence_band: high
cves:
  - id: CVE-2026-15450
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15450
---

The Nex Forms - Ultimate Form Builder - Lite plugin for WordPress (versions 9.2.3 and below) contains a critical path traversal vulnerability that enables arbitrary file deletion. The vulnerability exists within two specific AJAX handlers: insert_record() and delete_file(). The insert_record() function fails to validate input before storing it in the database, allowing an attacker to inject malicious file paths. The delete_file() function then retrieves this unsanitized path and passes it directly to the PHP unlink() function without performing path normalization, basename validation, or allowlist checks.

This flaw allows authenticated users - typically those with administrative privileges, though potentially lower depending on plugin configuration - to delete arbitrary files on the underlying web server. Successful exploitation can result in the deletion of critical WordPress files such as wp-config.php, which effectively forces a site re-installation or results in a complete denial of service. The vulnerability highlights the danger of passing user-supplied input directly to filesystem-modifying functions.

## Impact

Successful exploitation allows for the deletion of critical server files. In the context of a WordPress environment, the deletion of the wp-config.php file removes database connection settings, causing the site to become inaccessible and potentially allowing an attacker to initiate a fresh installation or redirect the site traffic. This poses a high risk to availability and system integrity for organizations relying on this plugin.

## Recommendation

- Update the Nex Forms - Ultimate Form Builder - Lite plugin to the latest version immediately to patch CVE-2026-15450.
- Audit the WordPress plugin directory and remove any plugins that are not actively maintained or required for business operations.
- Implement restrictive file system permissions on the web server to ensure that the web service user (e.g., www-data) cannot delete critical configuration or system files outside of designated upload directories.
- Review WordPress access logs for anomalous POST requests directed at the plugin's AJAX endpoints if indicators of compromise are suspected.
