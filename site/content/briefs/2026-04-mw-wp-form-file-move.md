---
title: MW WP Form WordPress Plugin Arbitrary File Move Vulnerability (CVE-2026-4347)
slug: 2026-04-mw-wp-form-file-move
description: The MW WP Form plugin for WordPress is vulnerable to arbitrary file moving due to insufficient file path validation, allowing unauthenticated attackers to move arbitrary files on the server, potentially leading to remote code execution.
date: "2026-04-02T06:16:23Z"
severities:
  - critical
tags:
  - wordpress
  - file-move
  - rce
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-4347
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4347
rules:
  - title: Detect MW WP Form Arbitrary File Move Attempt
    description: Detects potential attempts to exploit CVE-2026-4347 by monitoring for suspicious file path manipulations in requests to the MW WP Form plugin's upload handler.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect wp-config.php Access from Web Directory
    description: Detects attempts to access wp-config.php from a web-accessible directory, indicating potential exposure after a file move.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The MW WP Form plugin for WordPress is susceptible to an arbitrary file moving vulnerability identified as CVE-2026-4347. This flaw stems from a lack of proper file path validation within the 'generate_user_filepath' and 'move_temp_file_to_upload_dir' functions. All versions of the plugin up to and including 5.1.0 are affected. An unauthenticated attacker can exploit this vulnerability to move arbitrary files on the server, potentially overwriting or relocating critical system files. The most…
