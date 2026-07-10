---
title: Rails Active Storage Vulnerability Allows Arbitrary File Deletion
slug: 2024-01-rails-active-storage-delete
description: A vulnerability in Rails Active Storage allows attackers to delete arbitrary files in the storage directory by exploiting glob metacharacters in blob keys passed to `Dir.glob`.
date: "2024-01-10T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rails
  - active_storage
  - file_deletion
  - vulnerability
vendors:
  - Rails
products:
  - Active Storage
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33202
rules:
  - title: Detect Suspicious File Deletion in Active Storage Directory
    description: Detects suspicious file deletion activity within the Active Storage directory, potentially indicating exploitation of CVE-2026-33202.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Glob Metacharacters in File Paths
    description: Detects the presence of glob metacharacters in file paths, which could be a sign of an attempted directory traversal or arbitrary file deletion.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability exists in Active Storage, a component of the Rails web application framework, affecting versions prior to 8.1.2.1, 8.0.4.1, and 7.2.3.1. The vulnerability, identified as CVE-2026-33202, stems from the `DiskService#delete_prefixed` method's improper handling of glob metacharacters within blob keys. Specifically, the method passes blob keys directly to `Dir.glob` without proper escaping. An attacker who can control the input of blob keys, either through direct manipulation or custom generation, can inject glob metacharacters (e.g., *, ?, []) into the key. This allows the attacker to delete unintended files residing within the storage directory, potentially leading to data loss or service disruption. Successful exploitation requires the application to be configured to use the DiskService and the attacker to have a mechanism to influence the blob key.

## Attack Chain

1. The attacker identifies a Rails application utilizing Active Storage and the DiskService.
2. The attacker discovers or engineers a method to influence the generation or modification of blob keys. This might involve exploiting an existing application vulnerability (e.g., SQL injection) or manipulating application logic.
3. The attacker crafts a malicious blob key containing glob metacharacters (e.g., `evil*key`).
4. The application attempts to delete a file using the crafted blob key via `DiskService#delete_prefixed`.
5. `DiskService#delete_prefixed` passes the malicious blob key to `Dir.glob` without proper escaping.
6. `Dir.glob` interprets the glob metacharacters, causing it to match multiple files in the storage directory based on the attacker's crafted pattern. For example, `evil*key` could match `evilfilekey`, `evilotherkey`, etc.
7. `Dir.glob` deletes all matching files from the storage directory.
8. The attacker achieves arbitrary file deletion, potentially leading to data loss or service disruption.

## Impact

Successful exploitation of this vulnerability allows an attacker to delete arbitrary files within the Active Storage's configured storage directory. This could lead to significant data loss, potentially disrupting application functionality and impacting users. The severity is heightened when sensitive information is stored within the affected directories. Given the wide adoption of Rails, a successful widespread attack could impact a large number of applications across various sectors. The CVSS v3.1 base score for this vulnerability is 9.1 (Critical).

## Recommendation

*   Upgrade to Active Storage versions 8.1.2.1, 8.0.4.1, or 7.2.3.1 or later to incorporate the patch for CVE-2026-33202.
*   Implement input validation and sanitization on blob keys to prevent the injection of glob metacharacters.
*   Monitor application logs for suspicious file deletion activity, particularly within the Active Storage storage directory, using the provided Sigma rule.
*   Implement principle of least privilege on the storage directory to limit the impact of file deletion.
