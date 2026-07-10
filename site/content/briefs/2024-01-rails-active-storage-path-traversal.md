---
title: Rails Active Storage Path Traversal Vulnerability
slug: 2024-01-rails-active-storage-path-traversal
description: A path traversal vulnerability (CVE-2026-33195) exists in Rails Active Storage's DiskService#path_for, potentially allowing attackers to read, write, or delete arbitrary files on the server by crafting blob keys with path traversal sequences, impacting applications that pass user input as blob keys.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rails
  - active storage
  - path traversal
  - cve-2026-33195
vendors:
  - Ruby on Rails
products:
  - Active Storage
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-9xrj-h377-fr87
rules:
  - title: Detect Rails Active Storage Path Traversal Attempt
    description: Detects attempts to exploit the Rails Active Storage path traversal vulnerability by identifying suspicious file access patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Rails Active Storage Path Traversal - POST Request
    description: Detects attempts to exploit the Rails Active Storage path traversal vulnerability via POST requests containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability has been identified in the Active Storage component of Ruby on Rails. Specifically, the vulnerability resides within the `DiskService#path_for` method. This method lacks proper validation to ensure that the resolved filesystem path remains within the designated storage root directory. An attacker can exploit this by crafting a blob key containing path traversal sequences, such as "../", to navigate outside the intended storage area. This can lead to unauthorized access, potentially allowing the reading, writing, or deletion of arbitrary files on the server. This vulnerability particularly impacts applications where user-supplied input is used to construct blob keys. The affected versions are Active Storage versions before 7.2.3.1, versions 8.0.0.beta1 up to 8.0.4.1, and versions 8.1.0.beta1 up to 8.1.2.1. The CVE associated with this vulnerability is CVE-2026-33195.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of Rails Active Storage.
2. The attacker finds an endpoint where user-controlled input is used as a blob key for Active Storage.
3. The attacker crafts a malicious blob key containing path traversal sequences (e.g., "../../../etc/passwd").
4. The application uses the attacker-controlled blob key within the `DiskService#path_for` method.
5. Due to insufficient validation, `DiskService#path_for` resolves a file path outside the intended storage directory.
6. The application attempts to read, write, or delete a file based on the attacker-controlled path.
7. The attacker gains unauthorized access to sensitive files or modifies critical system configurations.
8. The attacker achieves arbitrary code execution or data exfiltration by leveraging the ability to write to arbitrary files.

## Impact

Successful exploitation of this vulnerability allows attackers to read, write, or delete arbitrary files on the server. The number of affected applications is currently unknown, but any application using a vulnerable version of Rails Active Storage and processing user-supplied blob keys is at risk. This can result in complete compromise of the affected server, including data theft, system modification, and denial of service. The severity of the impact depends on the privileges of the Rails application and the sensitivity of the data stored on the server.

## Recommendation

*   Upgrade to the latest patched versions of Active Storage: versions >= 7.2.3.1, >= 8.0.4.1, or >= 8.1.2.1 to remediate CVE-2026-33195.
*   Implement server-side validation to sanitize blob keys and prevent path traversal attempts before passing them to `DiskService#path_for`.
*   Deploy the Sigma rule "Detect Rails Active Storage Path Traversal Attempt" to monitor for exploitation attempts.
*   Review application code to ensure that user-provided input is not directly used as blob keys without proper sanitization.
