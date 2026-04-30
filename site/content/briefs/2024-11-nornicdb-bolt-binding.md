---
title: NornicDB Improper Network Binding Exposes Bolt Server
slug: 2024-11-nornicdb-bolt-binding
description: NornicDB versions prior to 1.0.42-hotfix have an improper network binding vulnerability in its Bolt server, allowing unauthorized remote access because the `--address` CLI flag is not correctly plumbed through to the Bolt server config, causing the Bolt listener to always bind to the wildcard address and expose the database with default credentials.
date: "2024-11-02T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - network-binding
  - misconfiguration
  - graph-database
products:
  - nornicdb
affected_os:
  - darwin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Collect Credentials
references:
  - https://github.com/advisories/GHSA-2hp7-65r3-wv54
rules:
  - title: Detect NornicDB Bolt Server Wildcard Binding
    description: Detects NornicDB Bolt server listening on all interfaces (0.0.0.0 or ::) by checking for the port 7687 being bound to a non-loopback address.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect NornicDB Bolt Server Wildcard Binding (IPv6)
    description: Detects NornicDB Bolt server listening on all IPv6 interfaces.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

NornicDB versions prior to 1.0.42-hotfix are vulnerable to an improper network binding issue affecting the Bolt server. The vulnerability stems from the `--address` CLI flag (and `NORNICDB_ADDRESS` / `server.host` config key) not being correctly applied to the Bolt server configuration. Consequently, the Bolt listener always binds to the wildcard address (0.0.0.0), irrespective of user-defined configurations. This default behavior exposes the graph database with its default `admin:password` credentials to unauthorized access. An attacker on the same network can exploit this vulnerability to issue arbitrary Cypher queries, potentially leading to unauthorized data access, modification, or deletion. This issue was identified in version 1.0.39, built from commit afe7c9d, on macOS (darwin 25.4.0, arm64).

## Attack Chain

1.  An attacker identifies a NornicDB instance running on a local network (LAN).
2.  The attacker scans the network for open port 7687, the default Bolt port, on the target machine.
3.  The attacker connects to the open Bolt port (7687) on the target NornicDB instance using `nc -z 192.168.x.y 7687`.
4.  The attacker attempts to authenticate to the Bolt server using the default credentials `admin:password`.
5.  Upon successful authentication, the attacker issues arbitrary Cypher queries to read, write, or delete nodes within the graph database.
6.  The attacker exfiltrates sensitive data from the database using Cypher queries.
7.  The attacker modifies or deletes critical data within the database, causing data integrity issues or service disruption.

## Impact

The vulnerability allows unauthorized remote access to NornicDB instances with default configurations. Attackers can exploit this flaw to issue arbitrary Cypher queries, potentially leading to complete database compromise. If the NornicDB instance contains sensitive information, successful exploitation could result in data breaches, financial losses, and reputational damage. Users following the README and reasonably assuming that `--address 127.0.0.1` (the documented default) binds *both* protocols to localhost are particularly at risk.

## Recommendation

*   Upgrade NornicDB to version 1.0.42-hotfix or later to patch the improper network binding vulnerability.
*   Apply host-firewall rules (e.g., macOS `pf`) blocking non-loopback connections to port 7687 as a workaround until the upgrade can be performed, as suggested in the advisory.
*   Deploy the Sigma rule `Detect NornicDB Bolt Server Wildcard Binding` to identify instances with exposed Bolt ports on all interfaces.
