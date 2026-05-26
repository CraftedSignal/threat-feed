---
title: yeoman-environment Vulnerable to Arbitrary Package Installation Leading to RCE (CVE-2026-42089)
slug: 2026-05-yeoman-rce
description: Versions of yeoman-environment ranging from 2.9.0 to before 6.0.1 install missing local generator packages from caller-supplied package names without user confirmation, potentially leading to arbitrary package installation and code execution in downstream consumers when attacker-controlled project configuration is passed.
date: "2026-05-26T23:12:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - supply-chain
  - CVE-2026-42089
  - yeoman
vendors:
  - yeoman
products:
  - yeoman-environment
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-vv9j-gjw2-j8wp
  - https://github.com/yeoman/environment/pull/753
  - https://github.com/yeoman/environment/commit/78d2af7e60294784b8a8b3b3b5099c6874b6a1fa
rules:
  - title: Detect CVE-2026-42089 Exploitation Attempt via Suspicious NPM Install
    description: Detects CVE-2026-42089 exploitation — Monitors process creation for npm install commands with suspicious arguments or package names that could indicate an attempt to install malicious packages without user confirmation.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1189
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-42089 Exploitation Attempt via Malicious Generator Package Installation
    description: Detects CVE-2026-42089 exploitation — Monitors process creation for node processes executing code from a recently installed npm package within the yeoman generators directory, indicating a potential RCE.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1189
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `yeoman-environment` package, a core component of the Yeoman scaffolding tool, is susceptible to arbitrary package installation due to insufficient user confirmation checks. Specifically, versions 2.9.0 through 6.0.0 are affected. This vulnerability (CVE-2026-42089) stems from the `installLocalGenerators()` method, which directly calls `repository.install()` without prompting the user for confirmation. An attacker can exploit this by manipulating project configurations passed to downstream consumers, causing the installation of malicious packages. This can lead to arbitrary code execution during the CLI bootstrap process. The fix was released in version 6.0.1, which introduced an interactive confirmation prompt before installation.

## Attack Chain

1.  An attacker crafts a malicious project configuration file.
2.  The attacker leverages a downstream consumer application that utilizes `yeoman-environment` and passes the attacker-controlled project configuration to it.
3.  The `installLocalGenerators()` function within `yeoman-environment` is triggered.
4.  Due to the vulnerability, the `repository.install()` method is called without user confirmation, using package names supplied in the malicious configuration.
5.  The attacker-specified packages are downloaded and installed from the npm registry (or a malicious mirror).
6.  The installed packages execute arbitrary code during the CLI bootstrap, potentially granting the attacker control over the system.
7.  The attacker establishes persistence through scheduled tasks or startup scripts.
8.  The attacker performs lateral movement within the network to compromise additional systems.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve arbitrary code execution on systems using vulnerable versions of `yeoman-environment`. This can lead to complete system compromise, data theft, and further propagation of the attack within the network. The severity is high due to the potential for remote code execution without user interaction.

## Recommendation

*   Upgrade `yeoman-environment` to version 6.0.1 or later to incorporate the fix that adds an interactive confirmation prompt before installation.
*   Deploy the Sigma rules provided below to detect attempts to exploit CVE-2026-42089 by monitoring for suspicious npm package installations via CLI.
*   Implement input validation and sanitization on project configuration files to prevent attackers from injecting malicious package names.
*   Monitor process creation events for unusual or unexpected processes spawned by npm or node.
