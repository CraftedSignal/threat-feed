---
title: Juju Controller Vulnerable to Unauthorized Database Access Due to Improper TLS Configuration
slug: 2026-04-juju-tls-vuln
description: Juju controller versions 3.2.0 up to 3.6.20 and 4.0.5 are vulnerable to unauthorized database access due to improper TLS client/server authentication and certificate verification, allowing an attacker with network access to modify all information, escalate privileges, and open firewall ports.
date: "2026-04-02T00:03:36Z"
severities:
  - critical
tags:
  - juju
  - dqlite
  - tls
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-gvrj-cjch-728p
  - https://github.com/juju/juju/blob/001318f51ac456602aef20b123684f1eeeae9a77/internal/database/node.go#L312-L324
rules:
  - title: Detect Unauthorized Connection to Juju Dqlite Port
    description: Detects network connections to the Juju Dqlite port (17666) from unexpected source IP addresses, indicating a potential unauthorized attempt to join the cluster.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Suspicious Dqlite Database Modification via Command Line
    description: Detects suspicious command-line activity indicative of unauthorized database modification using tools like dqlite-demo.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Juju, a service orchestration tool, contains a critical vulnerability related to improper TLS configuration within its Dqlite database cluster. This vulnerability affects Juju controller versions 3.2.0 up to 3.6.20 and 4.0.5. The lack of client certificate checking and server certificate verification allows an attacker with network route-ability to the Juju controller's Dqlite cluster endpoint (port 17666) to join the cluster without proper authentication. This grants the attacker the ability…
