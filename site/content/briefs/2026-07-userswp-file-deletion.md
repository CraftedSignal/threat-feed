---
title: UsersWP Plugin Arbitrary File Deletion (CVE-2026-13492)
slug: 2026-07-userswp-file-deletion
description: The UsersWP plugin for WordPress contains an Arbitrary File Deletion vulnerability, CVE-2026-13492, in versions up to and including 1.2.65, allowing an authenticated attacker with Subscriber-level access or higher to exploit insufficient validation in file-field values combined with an AJAX handler that lacks proper path canonicalization to delete arbitrary files on the server, including critical files like `wp-config.php`, leading to system impact.
date: "2026-07-09T19:18:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - vulnerability
  - web
  - file-deletion
  - remote-code-execution
vendors:
  - UsersWP
  - WordPress
products:
  - UsersWP plugin <= 1.2.65
  - WordPress
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The exploitation involves an AJAX handler, implying client-side scripting or direct HTTP requests that simulate AJAX.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: This makes it possible for authenticated attackers... to delete arbitrary files on the affected site's server, including wp-config.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1491
    technique_name: Defacement
    evidence: to delete arbitrary files on the affected site's server, including wp-config.
    confidence_band: high
cves:
  - id: CVE-2026-13492
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13492
rules:
  - title: Detects CVE-2026-13492 Exploitation - UsersWP Arbitrary File Deletion Attempt
    description: Detects exploitation attempts of CVE-2026-13492, an arbitrary file deletion vulnerability in the UsersWP plugin, by monitoring for HTTP POST requests to the `userswp_upload_file_remove` AJAX action containing directory traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1070.004
      - T1491
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, CVE-2026-13492, has been identified in the UsersWP plugin for WordPress, affecting versions up to and including 1.2.65. This flaw permits authenticated attackers with Subscriber-level privileges or higher to perform arbitrary file deletion on the hosting server. The vulnerability stems from inadequate sanitization of file-field values within the `UsersWP_Validation::validate_fields()` function, which allows directory traversal sequences to persist. Subsequently, the `UsersWP_Forms::upload_file_remove()` AJAX handler, responsible for file removal, constructs target paths by concatenating an uploads base directory with an attacker-controlled metadata value without proper realpath canonicalization or boundary checks. This allows a malicious actor to delete sensitive system files, such as `wp-config.php`, leading to potential denial of service or further compromise of the WordPress instance.

## Attack Chain

1. An authenticated attacker, with at least Subscriber-level privileges on the WordPress site, identifies the vulnerable UsersWP plugin.
2. The attacker crafts a malicious HTTP request targeting the `UsersWP_Forms::upload_file_remove()` AJAX handler.
3. The request includes a specially crafted "file-field" parameter containing directory traversal sequences (e.g., `../../../../`).
4. The `UsersWP_Validation::validate_fields()` function processes this input but fails to properly sanitize the directory traversal sequences.
5. The `upload_file_remove()` AJAX handler receives the unsanitized path and constructs a full file path for deletion.
6. This construction involves concatenating the WordPress uploads base directory with the attacker-controlled, directory-traversal-laden path, without performing `realpath` canonicalization or boundary checks.
7. The handler then invokes the `unlink()` function with the maliciously constructed arbitrary file path.
8. This results in the deletion of arbitrary files on the web server, potentially including critical files like `wp-config.php`, leading to site unavailability or further compromise.

## Impact

The arbitrary file deletion vulnerability (CVE-2026-13492) allows authenticated attackers to delete critical files on the victim's WordPress server, including the `wp-config.php` file, which contains database credentials and other vital configuration settings. Successful exploitation can lead to a complete denial of service for the website, requiring manual intervention to restore functionality. Furthermore, the ability to delete arbitrary files could be leveraged by attackers as a step towards achieving greater compromise, such as clearing logs to evade detection or disrupting security mechanisms. The CVSS v3.1 Base Score of 8.8 reflects the high severity of this vulnerability.

## Recommendation

* Immediately update the UsersWP plugin to a version greater than 1.2.65 to patch CVE-2026-13492.
* Review web server access logs for unusual HTTP POST requests to AJAX endpoints, specifically `wp-admin/admin-ajax.php?action=userswp_upload_file_remove`, containing path traversal sequences (e.g., `../`, `..\`) in parameters, to detect potential exploitation attempts of CVE-2026-13492.
