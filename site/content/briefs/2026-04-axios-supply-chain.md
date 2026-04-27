---
title: Compromised Axios Library Leads to RAT Deployment via @usebruno/cli
slug: 2026-04-axios-supply-chain
description: Compromised versions of the `axios` npm package introduced a hidden dependency deploying a cross-platform Remote Access Trojan (RAT), impacting users of `@usebruno/cli` who ran `npm install` between 00:21 UTC and ~03:30 UTC on March 31, 2026, potentially leading to credential exfiltration.
date: "2026-04-03T12:00:00Z"
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

On March 31, 2026, a supply chain attack targeted the `axios` npm package, a widely used HTTP client library for JavaScript. Compromised versions 1.14.1 and 0.30.4 of the library were injected with malicious code that installed a cross-platform Remote Access Trojan (RAT) on systems that installed the affected versions of `@usebruno/cli`. This attack specifically impacted users of the `@usebruno/cli` who performed an `npm install` within a roughly 3-hour window, between 00:21 UTC and 03:30 UTC…
