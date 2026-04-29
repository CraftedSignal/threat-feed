---
title: Juju Controller Vulnerable to Unauthorized Database Access Due to Improper TLS Configuration
slug: 2026-04-juju-tls-vuln
description: Juju controller versions 3.2.0 up to 3.6.20 and 4.0.5 are vulnerable to unauthorized database access due to improper TLS client/server authentication and certificate verification, allowing an attacker with network access to modify all information, escalate privileges, and open firewall ports.
date: "2026-04-02T00:03:36Z"
type: coverage
types:
  - coverage
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

Juju, a service orchestration tool, contains a critical vulnerability related to improper TLS configuration within its Dqlite database cluster. This vulnerability affects Juju controller versions 3.2.0 up to 3.6.20 and 4.0.5. The lack of client certificate checking and server certificate verification allows an attacker with network route-ability to the Juju controller's Dqlite cluster endpoint (port 17666) to join the cluster without proper authentication. This grants the attacker the ability to read and modify all information within the database, including sensitive user credentials and system configurations. Exploitation of this vulnerability enables privilege escalation, unauthorized access to resources, and potentially the ability to open firewall ports, leading to a complete compromise of the Juju controller and managed services. Patches are available in Juju versions 3.6.20 and 4.0.5.

## Attack Chain

1. The attacker gains network access to the target Juju controller's Dqlite cluster endpoint, typically port 17666.
2. The attacker uses a tool like `dqlite-demo` or a custom-built application leveraging the go-dqlite library to attempt to join the Dqlite cluster.
3. Due to the missing client certificate verification, the attacker's connection is accepted without proper authentication.
4. The attacker switches to the `controller` database using the `.switch controller` command within the dqlite shell.
5. The attacker queries the `user` table to identify existing users and their associated privileges using `select * from user;`.
6. The attacker modifies the `display_name` of the `admin` user within the `user` table using an `update` SQL command, for example: `update user set display_name='Compromised Admin' where name='admin';`.
7. The attacker could further modify credentials, add new administrative users, or modify system configurations within the database.
8. The attacker leverages their unauthorized access to escalate privileges, compromise managed services, and potentially open firewall ports, gaining complete control over the Juju environment.

## Impact

Successful exploitation of this vulnerability allows an attacker to completely compromise the Juju controller. The attacker can read and modify all information within the Juju database, including user credentials, application configurations, and system settings. This can lead to the compromise of all applications and services managed by the Juju controller.  Privilege escalation allows the attacker to gain administrative control over the Juju environment. The ability to open firewall ports provides a pathway for lateral movement and further exploitation of the compromised network.

## Recommendation

*   Immediately upgrade Juju controllers to versions 3.6.20 or 4.0.5 to apply the patches that address this vulnerability.
*   Implement restrictive firewall rules to limit access to port 17666 on Juju controllers, as recommended in the advisory. Ensure only other controller IP addresses can connect to this port.
*   Deploy the following Sigma rule to detect unauthorized connections to the Dqlite database (see Sigma rule below).
*   Monitor network connections to port 17666 for unexpected source IP addresses (see IOCs).
