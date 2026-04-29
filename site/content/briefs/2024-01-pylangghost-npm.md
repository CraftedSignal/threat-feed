---
title: PylangGhost RAT Observed on npm Registry
slug: 2024-01-pylangghost-npm
description: A new remote access trojan (RAT) named PylangGhost has been observed on the npm registry, posing a supply chain risk to developers and applications using affected packages.
date: "2026-03-16T04:45:53Z"
type: coverage
types:
  - coverage
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

A new remote access trojan (RAT) named PylangGhost has been discovered on the npm registry. This marks the first known instance of this specific RAT being distributed via a software supply chain attack on the npm ecosystem. The RAT is named for its use of Python and potentially for obfuscation or evasion techniques. The affected npm packages are designed to inject malicious code into projects that depend on them. This malicious code facilitates unauthorized remote access to infected systems, thereby providing threat actors with the ability to exfiltrate sensitive data, deploy further malware, or perform other malicious activities. This is a supply chain attack that endangers developers and applications.

## Attack Chain

1.  A developer installs a malicious package from the npm registry containing PylangGhost.
2.  During the installation process, a post-install script or similar mechanism executes, injecting the PylangGhost RAT into the developer's environment.
3.  The RAT establishes a connection to a command-and-control (C2) server controlled by the attacker.
4.  The C2 server sends commands to the infected system, instructing the RAT to perform specific actions.
5.  The RAT executes the commands, potentially including data exfiltration, downloading and executing additional payloads, or establishing persistence.
6.  Sensitive data, such as credentials, API keys, or source code, is exfiltrated from the compromised system to the C2 server.
7.  The attacker gains remote access and control over the compromised system, enabling further malicious activities.

## Impact

The presence of PylangGhost on the npm registry introduces a significant supply chain risk.  Successful infection allows attackers to gain remote access to developer systems, potentially leading to the theft of sensitive source code, credentials, and other proprietary information. The compromise can extend to applications built using the infected packages, impacting downstream users and potentially leading to widespread data breaches or service disruptions. The number of affected victims is currently unknown, but the risk is widespread due to the popularity of the npm registry.

## Recommendation

*   Monitor npm package installations for suspicious post-install scripts or unexpected network connections (see related Sigma rules).
*   Implement strong dependency scanning tools to identify and remove potentially malicious packages from your projects.
*   Analyze network connection logs for connections to unusual or malicious domains after npm package installations (see related Sigma rules).
*   Enable process monitoring for any processes spawned during or after npm package installations.
