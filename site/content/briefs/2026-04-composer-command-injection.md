---
title: Composer Command Injection via Malicious Perforce Repository
slug: 2026-04-composer-command-injection
description: Composer is vulnerable to command injection via a malicious Perforce repository due to improper escaping of user-supplied Perforce connection parameters, potentially leading to arbitrary command execution in the context of the user running Composer.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
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

Composer, a dependency manager for PHP, is susceptible to a command injection vulnerability (CVE-2026-40176) in versions 2.0.0 before 2.2.27 and versions 2.3.0 before 2.9.6. The vulnerability resides in the `Perforce::generateP4Command()` method, which improperly escapes user-supplied Perforce connection parameters (port, user, client) when constructing shell commands. This allows an attacker who controls a repository configuration, specifically within a malicious `composer.json` file declaring a Perforce VCS repository, to inject arbitrary commands. The injected commands are executed in the context of the user running Composer, even if Perforce is not installed. This vulnerability can be exploited if Composer is run on untrusted projects with attacker-supplied `composer.json` files.

## Attack Chain

1. An attacker crafts a malicious `composer.json` file.
2. The malicious `composer.json` declares a Perforce VCS repository.
3. The `composer.json` contains injected commands within the Perforce connection parameters (port, user, client).
4. A user unknowingly executes a Composer command (e.g., `composer install`) in a directory containing the malicious `composer.json`.
5. Composer parses the `composer.json` and calls the `Perforce::generateP4Command()` method.
6. The `Perforce::generateP4Command()` method constructs a shell command using the attacker-controlled, unescaped Perforce connection parameters.
7. Composer executes the injected command via `proc_open` or similar functions.
8. The attacker achieves arbitrary command execution in the context of the user running Composer, potentially leading to sensitive information disclosure, system compromise, or further malicious activities.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary commands on the victim's system with the privileges of the user running Composer. This can lead to complete system compromise, data exfiltration, or denial of service. While the number of victims is currently unknown, any system running a vulnerable version of Composer and processing untrusted `composer.json` files is at risk. The primary attack vector involves tricking developers into running Composer on projects containing malicious `composer.json` files.

## Recommendation

*   Upgrade Composer to version 2.2.27 or 2.9.6 or later to patch CVE-2026-40176.
*   Carefully inspect `composer.json` files from untrusted sources before running Composer to verify Perforce-related fields contain valid values.
*   Deploy the Sigma rule to detect command execution with suspicious arguments when composer executes and tune for your environment.
