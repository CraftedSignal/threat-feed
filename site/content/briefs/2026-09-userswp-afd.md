---
title: Arbitrary File Deletion in UsersWP WordPress Plugin
slug: 2026-09-userswp-afd
description: The UsersWP plugin for WordPress versions up to 1.2.70 allows authenticated attackers to delete arbitrary files on the web server via a path traversal vulnerability in the upload_file_remove() AJAX handler.
date: "2026-09-11T05:12:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:userswp:userswp:*:*:*:*:*:*:*:*
vendors:
  - UsersWP
products:
  - UsersWP (<= 1.2.70)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to delete arbitrary files on the affected site's server.
    confidence_band: high
cves:
  - id: CVE-2026-19991
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19991
rules:
  - title: Detect CVE-2026-19991 Exploitation Attempt
    description: Detects exploitation attempts against the UsersWP upload_file_remove() handler by monitoring for path traversal sequences in AJAX requests.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade UsersWP plugin to the latest version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-19991 mitigation
  mitigation_plan:
    - priority: immediate
      action: Upgrade UsersWP to version > 1.2.70
      owner: IT Operations
      addresses: CVE-2026-19991
---

The UsersWP WordPress plugin (versions 1.2.70 and below) contains an arbitrary file deletion vulnerability (CVE-2026-19991) triggered via the upload_file_remove() AJAX handler. The vulnerability stems from improper validation of user-supplied file path input. The plugin incorrectly validates inputs intended for file removal, as it fails to account for normalized path traversal sequences that emerge after processing. Specifically, when an attacker provides a crafted URL containing embedded upload base URL tokens, the plugin's helper function performs a global string replacement, transforming the input into a directory traversal sequence ('../../'). This path is then appended to the uploads base directory and passed to wp_delete_file() without canonicalization or containment checks. An authenticated attacker with at least Subscriber-level access can exploit this to remove sensitive files from the WordPress installation, including wp-config.php, which could lead to service disruption or site takeover.

## Impact

Successful exploitation allows an authenticated attacker to delete any file on the web server that the web server user has permission to modify. This can lead to the deletion of wp-config.php, forcing a site reinstallation, or other critical files, resulting in a denial-of-service condition or site compromise. The vulnerability affects all WordPress sites utilizing UsersWP version 1.2.70 or lower.

## Recommendation

- Upgrade the UsersWP plugin to a version higher than 1.2.70 immediately to remediate CVE-2026-19991.
- Implement a Web Application Firewall (WAF) rule to block POST requests containing path traversal sequences (e.g., '../') targeted at the AJAX handlers used by the plugin.
- Audit logs for unauthorized deletion attempts or anomalous file system activity originating from low-privileged Subscriber accounts.
