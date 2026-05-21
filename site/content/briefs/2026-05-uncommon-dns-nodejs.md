---
title: Uncommon DNS Requests via Bun or Node.js
slug: 2026-05-uncommon-dns-nodejs
description: Detection of uncommon DNS requests originating from Bun or Node.js processes, potentially indicating malicious code execution following a supply chain attack.
date: "2026-05-21T12:42:14Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - supply-chain
  - command-and-control
  - dns
  - nodejs
  - bun
vendors:
  - Elastic
products:
  - Elastic Endpoint
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
references:
  - https://github.com/nrwl/nx-console/issues/3139
rules:
  - title: Detect Uncommon DNS Request via Bun or Node.js (Process Name)
    description: Detects uncommon DNS requests initiated by Bun or Node.js processes based on process name.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - dns_query
      - windows
  - title: Detect Uncommon DNS Request via Bun or Node.js (Process Path)
    description: Detects uncommon DNS requests initiated by Bun or Node.js processes based on process path.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

This detection identifies unusual DNS requests originating from Node.js or Bun, which may indicate supply chain compromise. Node.js and Bun are JavaScript runtimes popular for web application development. Adversaries could compromise developer packages and inject malicious code, leading to the execution of unauthorized network activities. This rule is designed to detect such anomalous DNS requests, helping to identify potential data exfiltration or command and control activities resulting from compromised dependencies. Elastic recommends using Endpoint 9.3.0 or later.

## Attack Chain

1. A developer's machine is compromised through a supply chain attack on a Node.js or Bun package.
2. Malicious code is injected into the application's dependencies.
3. The application executes the malicious code when a user runs or builds the application.
4. The malicious code uses Node.js or Bun's networking capabilities to initiate a DNS request to an external domain.
5. The DNS request targets a domain not typically accessed by the application.
6. The DNS request is used to beacon to a command-and-control server or exfiltrate sensitive data.

## Impact

Compromised Node.js or Bun applications can lead to data theft, remote code execution, and unauthorized access to sensitive resources. Supply chain attacks targeting developer tools are a growing concern. This can affect any organization relying on potentially vulnerable packages within their applications.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Monitor network connections from Node.js and Bun processes, especially DNS requests to uncommon domains.
*   Implement software composition analysis (SCA) to identify and manage open-source dependencies and known vulnerabilities.
*   Enforce strict code review processes for changes to application dependencies.
