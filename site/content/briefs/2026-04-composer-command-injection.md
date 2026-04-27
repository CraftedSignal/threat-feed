---
title: Composer Command Injection via Malicious Perforce Repository
slug: 2026-04-composer-command-injection
description: Composer is vulnerable to command injection via a malicious Perforce repository due to improper escaping of user-supplied Perforce connection parameters, potentially leading to arbitrary command execution in the context of the user running Composer.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - composer
  - command-injection
  - php
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-wg36-wvj6-r67p
rules:
  - title: Detect Composer Command Injection via Perforce
    description: Detects command execution with suspicious Perforce parameters when invoked by composer, indicating potential command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1547.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Composer Command Injection via Perforce (Windows)
    description: Detects command execution with suspicious Perforce parameters when invoked by composer, indicating potential command injection on windows.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Composer, a dependency manager for PHP, is susceptible to a command injection vulnerability (CVE-2026-40176) in versions 2.0.0 before 2.2.27 and versions 2.3.0 before 2.9.6. The vulnerability resides in the `Perforce::generateP4Command()` method, which improperly escapes user-supplied Perforce connection parameters (port, user, client) when constructing shell commands. This allows an attacker who controls a repository configuration, specifically within a malicious `composer.json` file declaring…
