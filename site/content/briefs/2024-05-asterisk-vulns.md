---
title: Asterisk and Digium Certified Asterisk Vulnerabilities
slug: 2024-05-asterisk-vulns
description: An authenticated remote attacker can exploit vulnerabilities in Asterisk and Digium Certified Asterisk to achieve arbitrary code execution, denial of service, or information disclosure.
date: "2026-03-25T10:21:05Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - asterisk
  - voip
  - code-execution
  - dos
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.003
    technique_name: 'Event Triggered Execution: Windows Management Instrumentation Event Subscription'
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2022-2108
rules:
  - title: Asterisk Configuration Change Detection
    description: Detects suspicious changes to Asterisk configuration files.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - file_event
      - linux
  - title: Asterisk Suspicious Outbound Connection
    description: Detects Asterisk processes making outbound network connections to unusual ports.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Multiple vulnerabilities exist within Asterisk and Digium Certified Asterisk, potentially allowing a remote, authenticated attacker to perform several malicious actions. These actions include arbitrary code execution, which could lead to complete system compromise, denial-of-service (DoS) attacks, rendering the system unusable, and sensitive information disclosure, potentially leading to further exploitation. The scope of these vulnerabilities encompasses any system running a vulnerable version of Asterisk or Digium Certified Asterisk. Defenders should prioritize identifying and patching affected systems to prevent potential exploitation.

## Attack Chain

1.  The attacker authenticates to the Asterisk or Digium Certified Asterisk system using valid credentials.
2.  The attacker exploits a vulnerability allowing them to inject malicious code into a configuration file.
3.  The Asterisk process parses the modified configuration file, executing the injected code.
4.  The injected code establishes a reverse shell connection back to the attacker's system.
5.  The attacker leverages the reverse shell to gain interactive access to the Asterisk server.
6.  The attacker escalates privileges using publicly available exploits or further vulnerabilities within the system.
7.  The attacker installs persistent backdoors or modifies system configurations for long-term access.
8.  The attacker exfiltrates sensitive data or causes a denial-of-service condition by crashing critical processes.

## Impact

Successful exploitation of these vulnerabilities could have severe consequences. An attacker could gain complete control over the affected Asterisk or Digium Certified Asterisk systems. This could lead to disruption of communication services, exfiltration of sensitive call data, or the use of the compromised system as a launchpad for further attacks within the network. The impact includes potential financial losses, reputational damage, and legal liabilities due to data breaches.

## Recommendation

*   Review Asterisk and Digium Certified Asterisk logs for suspicious configuration changes using the provided Sigma rule `Asterisk Configuration Change Detection`.
*   Implement strong authentication and access controls to limit the potential for unauthorized access as a prerequisite for exploitation.
*   Continuously monitor Asterisk processes for unexpected outbound network connections using the Sigma rule `Asterisk Suspicious Outbound Connection`.
