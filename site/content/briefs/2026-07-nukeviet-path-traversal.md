---
title: 'NukeViet: Path Traversal to Arbitrary File Deletion in Edit Comment Function'
slug: 2026-07-nukeviet-path-traversal
description: An authenticated administrator in NukeViet is vulnerable to a path traversal flaw (CVE-2026-54065) in the Edit Comment admin function, allowing an attacker to inject a crafted `attach` parameter which, upon comment deletion, leads to arbitrary file deletion within the application root, causing a full application outage and exposing the install wizard.
date: "2026-07-13T17:57:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - arbitrary-file-deletion
  - web-vulnerability
  - cms
vendors:
  - NukeViet
products:
  - NukeViet (< 4.6.00)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Any file readable by the web server process within NV_ROOTDIR can be permanently deleted. Deleting config.php causes a full application outage and exposes the install wizard.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated administrator can delete arbitrary files... Log in as an administrator...
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-c9xg-64p9-f2jj
rules:
  - title: Detects CVE-2026-54065 Exploitation - NukeViet Path Traversal via Edit Comment
    description: Detects CVE-2026-54065 exploitation - HTTP POST requests to the NukeViet admin comment edit function with a crafted `attach` parameter containing path traversal sequences, indicative of an attempt to inject a malicious path for arbitrary file deletion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1078
      - T1485
    data_sources:
      - webserver
rules_count: 1
---

A high-severity path traversal vulnerability, tracked as CVE-2026-54065, affects NukeViet versions prior to 4.6.00. This flaw resides within the Edit Comment administrative function and can be exploited by an authenticated administrator. Attackers can leverage an unvalidated `attach` parameter in an HTTP POST request to inject path traversal sequences (e.g., `../../`) into the database. When a comment containing this malicious `attach` value is subsequently deleted, the `nv_deletefile()` function, which uses `realpath()` but lacks sufficient directory restriction, is tricked into deleting arbitrary files within the `NV_ROOTDIR`, such as `config.php`. This can lead to a complete application outage and exposure of the installation wizard, severely impacting the availability and integrity of the affected NukeViet instance.

## Attack Chain

1. An attacker gains or has access to administrator credentials for a NukeViet instance.
2. The attacker logs into the NukeViet admin panel and navigates to the "Comment Management" section.
3. The attacker intercepts the HTTP POST request made when editing an existing comment.
4. The attacker crafts the `attach` parameter in the POST request by prepending 26 arbitrary characters (e.g., `aaaaaaaaaaaaaaaaaaaaaaaaaa`) followed by a path traversal sequence leading to a critical file, such as `../../config.php`.
5. The vulnerable `substr()` function processes this crafted `attach` parameter, effectively storing `../../config.php` into the database due to incorrect length calculation and lack of validation.
6. The attacker then deletes the modified comment from the NukeViet admin panel.
7. During the comment deletion process, `del.php` retrieves the malicious `attach` value from the database and passes it to `nv_deletefile()`.
8. `nv_deletefile()` resolves the path to the target file (e.g., `config.php`) using `realpath()` and proceeds to delete it from the application root, bypassing directory restrictions.
9. The NukeViet application becomes inoperable due to the deletion of critical files like `config.php`, immediately redirecting to the install wizard.

## Impact

Successful exploitation of CVE-2026-54065 allows an authenticated administrator to permanently delete any file readable by the web server process within the NukeViet installation root directory (`NV_ROOTDIR`). The most significant impact is the deletion of `config.php`, which renders the NukeViet application entirely inoperable and automatically redirects users to the installation wizard, signifying a complete loss of application availability. This vulnerability has a CVSS v3.1 score of 8.7 (High), indicating high impact on integrity and availability with high privileges required but low attack complexity.

## Recommendation

* Patch CVE-2026-54065 immediately by upgrading NukeViet to version 4.6.00 or later to ensure the `nv_is_file()` validation is applied to the `attach` parameter.
* Implement web application firewall (WAF) rules to detect and block HTTP POST requests to `modules/comment/admin/edit.php` containing path traversal sequences (e.g., `../`, `..%2f`) within the `attach` parameter.
* Monitor web server logs for HTTP POST requests to `modules/comment/admin/edit.php` that contain unusual or path-like values in the `attach` parameter, particularly those with repeated directory traversal sequences, using the Sigma rule provided in this brief.
