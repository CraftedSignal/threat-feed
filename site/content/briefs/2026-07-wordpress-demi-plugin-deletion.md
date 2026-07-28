---
title: The Demi WordPress Plugin Vulnerable to Arbitrary Directory Deletion (CVE-2026-14490)
slug: 2026-07-wordpress-demi-plugin-deletion
description: Unauthenticated attackers can exploit CVE-2026-14490 in The Demi - One Click Demo Import, WP Backup & Site Migration WordPress plugin (versions up to and including 0.0.7) to achieve arbitrary directory deletion by retrieving a publicly exposed HMAC signing key and forging valid requests to a vulnerable AJAX handler.
date: "2026-07-28T07:18:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - plugin-vulnerability
  - arbitrary-deletion
  - web-vulnerability
vendors:
  - The Demi
products:
  - The Demi – One Click Demo Import, WP Backup & Site Migration plugin <= 0.0.7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: unauthenticated attacker who retrieves the exposed key can forge a valid signed state envelope to invoke `CleanDir::execute()`
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: makes it possible for unauthenticated attackers to recursively delete arbitrary directories on the server.
    confidence_band: high
cves:
  - id: CVE-2026-14490
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14490
---

CVE-2026-14490 describes a critical vulnerability affecting all versions up to 0.0.7 of The Demi - One Click Demo Import, WP Backup & Site Migration plugin for WordPress. This flaw, with a CVSS v3.1 Base Score of 7.5, allows unauthenticated attackers to recursively delete arbitrary directories on the server hosting the WordPress instance. The vulnerability stems from the plugin's insecure storage of its HMAC signing key and per-step restore token as dotfiles within a publicly accessible subdirectory of the WordPress uploads folder, without adequate protection such as `.htaccess` or index files. An unauthenticated attacker can retrieve this key, then use it to forge a valid signed state envelope for the `demi_restore_step` AJAX handler. This handler explicitly accepts the on-disk signing key as an alternative to standard WordPress authentication checks and processes a caller-supplied absolute path for deletion without validation or allow-listing. The exploitation of this vulnerability can lead to severe data loss and denial of service.

## Attack Chain

1. An attacker identifies a WordPress site running The Demi - One Click Demo Import, WP Backup & Site Migration plugin version 0.0.7 or earlier.
2. The attacker sends a direct HTTP GET request to a known publicly accessible subdirectory within the WordPress uploads folder (e.g., `/wp-content/uploads/demi-backup/`) to locate and retrieve the exposed `.hmac_key` dotfile.
3. The web server, lacking proper `.htaccess` or index file protection for the directory, serves the `.hmac_key` file, allowing the attacker to obtain the HMAC signing key.
4. The attacker uses the retrieved HMAC signing key to craft a malicious POST request to the `/wp-admin/admin-ajax.php` endpoint, setting the `action` parameter to `demi_restore_step`.
5. Within the POST request, the attacker includes a forged signed state envelope containing the stolen HMAC key and a `path` parameter specifying an absolute path to an arbitrary target directory on the server (e.g., `/var/www/html`, `/etc`, or `/`).
6. The vulnerable `demi_restore_step` AJAX handler processes the request, bypassing authentication checks due to the valid forged envelope.
7. The handler invokes the `CleanDir::execute()` function with the attacker-supplied absolute path, which is not subjected to allow-listing or path canonicalization checks.
8. The `CleanDir::execute()` function recursively deletes the specified arbitrary directory on the server, resulting in data destruction, site defacement, or complete denial of service.

## Impact

Successful exploitation of CVE-2026-14490 allows unauthenticated attackers to recursively delete any directory on the compromised server. This can lead to catastrophic consequences, including complete deletion of the WordPress installation files, sensitive configuration files, other website data, or even critical operating system directories. The primary observed impacts include severe data loss, web application defacement, and extended denial of service for the affected WordPress instance and potentially the entire server. Organizations face significant operational disruption and recovery costs if an attacker targets their essential system directories.

## Recommendation

* Immediately update The Demi - One Click Demo Import, WP Backup & Site Migration plugin to a patched version to remediate CVE-2026-14490.
* Monitor web server access logs for unusual requests to dotfiles (e.g., `.hmac_key`) within publicly accessible directories like `/wp-content/uploads/demi-backup/`.
* Implement web application firewall (WAF) rules to detect and block requests attempting to access sensitive dotfiles or sending POST requests to `/wp-admin/admin-ajax.php` with suspicious `demi_restore_step` actions and absolute paths in the `path` parameter.
* Ensure proper file system permissions and web server configurations are in place to prevent direct access to sensitive configuration files or dotfiles, especially in `/wp-content/uploads/` and its subdirectories.
