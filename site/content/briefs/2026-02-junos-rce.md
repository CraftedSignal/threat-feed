---
title: Critical Unauthenticated RCE Vulnerability in Junos OS Evolved
slug: 2026-02-junos-rce
description: A critical unauthenticated remote code execution vulnerability, CVE-2026-21902, exists in Juniper Networks Junos OS Evolved PTX Series, allowing a network-based attacker to execute code as root, requiring immediate patching and increased monitoring.
date: "2026-02-27T15:13:48Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - junos
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://ccb.belgium.be/advisories/warning-critical-unauthenticated-rce-vulnerability-junos-os-evolved-patch-immediately
  - https://supportportal.juniper.net/s/article/2026-02-Out-of-Cycle-Security-Bulletin-Junos-OS-Evolved-PTX-Series-A-vulnerability-allows-a-unauthenticated-network-based-attacker-to-execute-code-as-root-CVE-2026-21902
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21902
rules:
  - title: Potential Junos OS Evolved CVE-2026-21902 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-21902 by monitoring for unusual processes spawned by the Junos OS anomaly detection framework.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-21902
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Junos OS Evolved - Suspicious Outbound Network Connection
    description: Detects suspicious outbound network connections originating from the Junos OS Evolved device itself.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - cve-2026-21902
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-21902, has been identified in Juniper Networks Junos OS Evolved PTX Series versions before 25.4R1-S1-EVO and 25.4R2-EVO. This vulnerability resides in the on-box anomaly detection framework and allows an unauthenticated, network-based attacker to execute arbitrary code as the root user. Given the pivotal role of PTX series routers in data centers and internet service provider networks, a successful exploit can lead to significant disruption, enabling attackers…
