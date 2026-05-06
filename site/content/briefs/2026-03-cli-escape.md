---
title: Unauthenticated CLI Escape Vulnerability (CVE-2026-3587)
slug: 2026-03-cli-escape
description: An unauthenticated remote attacker can exploit a hidden function in the CLI prompt to escape the restricted interface of a device, leading to full compromise and root access on the underlying Linux-based OS, as described in CVE-2026-3587.
date: "2026-03-24T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve
  - cli
  - privilege_escalation
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3587
  - https://certvde.com/de/advisories/VDE-2026-020
rules:
  - title: Detect Potential CLI Escape via Process Creation
    description: Detects suspicious process creation events originating from the CLI, which could indicate an attempt to escape the restricted environment and execute arbitrary commands.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect CLI Interface Access from Unusual Source IP
    description: Detects network connections to the CLI interface originating from unusual or unexpected source IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-3587 describes a critical vulnerability affecting devices with a command-line interface (CLI). An unauthenticated remote attacker can exploit a hidden function within the CLI prompt to bypass intended restrictions and gain unauthorized access. This vulnerability allows the attacker to escape the restricted CLI environment and obtain root privileges on the underlying Linux-based operating system, leading to a complete system compromise. The vulnerability was reported by CERT VDE. A…
