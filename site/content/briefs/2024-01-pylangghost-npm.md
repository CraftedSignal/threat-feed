---
title: PylangGhost RAT Observed on npm Registry
slug: 2024-01-pylangghost-npm
description: A new remote access trojan (RAT) named PylangGhost has been observed on the npm registry, posing a supply chain risk to developers and applications using affected packages.
date: "2026-03-16T04:45:53Z"
severities:
  - high
tags:
  - supply-chain
  - rat
  - npm
  - pylangghost
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rv04vm/first_instance_of_pylangghost_rat_observed_on_npm/
  - https://kmsec.uk/blog/pylangghost-npm/
rules:
  - title: Suspicious Network Connection After NPM Install
    description: Detects network connections initiated shortly after an npm install, which could indicate a malicious post-install script executing.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Post-Install Script Execution
    description: Detects execution of suspicious programs by the node process following a potential npm install
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A new remote access trojan (RAT) named PylangGhost has been discovered on the npm registry. This marks the first known instance of this specific RAT being distributed via a software supply chain attack on the npm ecosystem. The RAT is named for its use of Python and potentially for obfuscation or evasion techniques. The affected npm packages are designed to inject malicious code into projects that depend on them. This malicious code facilitates unauthorized remote access to infected systems…
