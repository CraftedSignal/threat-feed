---
title: Compromised Axios Library Leads to RAT Deployment via @usebruno/cli
slug: 2026-04-axios-supply-chain
description: Compromised versions of the `axios` npm package introduced a hidden dependency deploying a cross-platform Remote Access Trojan (RAT), impacting users of `@usebruno/cli` who ran `npm install` between 00:21 UTC and ~03:30 UTC on March 31, 2026, potentially leading to credential exfiltration.
date: "2026-04-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - supply-chain
  - npm
  - rat
  - credential-theft
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-658g-p7jg-wx5g
  - https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat
iocs:
  - type: url
    value: https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious Process Spawned by NPM
    description: Detects suspicious processes spawned by npm or node, which could indicate malicious activity during package installation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows|linux|macos
  - title: Detect Outbound Network Connection from postinstall Script
    description: Detects network connections initiated from a process spawned during the postinstall phase, which could indicate a RAT calling home.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows|linux|macos
rules_count: 2
---

On March 31, 2026, a supply chain attack targeted the `axios` npm package, a widely used HTTP client library for JavaScript. Compromised versions 1.14.1 and 0.30.4 of the library were injected with malicious code that installed a cross-platform Remote Access Trojan (RAT) on systems that installed the affected versions of `@usebruno/cli`. This attack specifically impacted users of the `@usebruno/cli` who performed an `npm install` within a roughly 3-hour window, between 00:21 UTC and 03:30 UTC. The malicious code was designed to execute during the `postinstall` phase of the package installation, indicating a targeted effort to compromise developer environments. This incident highlights the increasing risk of supply chain attacks targeting open-source software and the importance of verifying the integrity of third-party dependencies.

## Attack Chain

1.  Attacker compromises the `axios` npm package, injecting malicious code into versions 1.14.1 and 0.30.4.
2.  The compromised `axios` package is published to the npm registry.
3.  A user of `@usebruno/cli` executes `npm install` within the attack window (00:21 UTC - 03:30 UTC on March 31, 2026).
4.  The npm package manager resolves the dependency chain and downloads the compromised `axios` package as a dependency of `@usebruno/cli`.
5.  The malicious code within the `axios` package executes during the `postinstall` script phase of the installation process.
6.  The `postinstall` script downloads and installs a cross-platform Remote Access Trojan (RAT) on the user's system.
7.  The RAT establishes a connection to a remote command-and-control (C2) server.
8.  The attacker uses the RAT to exfiltrate credentials and other sensitive data from the compromised system.

## Impact

This supply chain attack could have resulted in widespread compromise of developer systems that used the `@usebruno/cli`. While the number of affected users is unknown, the incident could have led to the exfiltration of sensitive credentials and proprietary source code, potentially enabling further attacks against the affected organizations and their customers. The incident underscores the need for robust security measures in software development pipelines and continuous monitoring of third-party dependencies for malicious activity.

## Recommendation

*   If `@usebruno/cli` was installed during the affected window, reinstall dependencies to ensure a clean version of `axios` is used (reference: Impact section).
*   Rotate all credentials and secrets that were present on systems where `@usebruno/cli` was installed during the affected window (reference: Impact section).
*   Review and implement the security guidance provided in the Aikido Security blog post to further harden your systems (reference: https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat).
*   Monitor process creation events for unusual processes spawned by npm or node processes, using the provided Sigma rule (reference: Sigma rule - "Detect Suspicious Process Spawned by NPM").
