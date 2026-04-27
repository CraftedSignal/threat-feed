---
title: NornicDB Improper Network Binding Exposes Bolt Server
slug: 2024-11-nornicdb-bolt-binding
description: NornicDB versions prior to 1.0.42-hotfix have an improper network binding vulnerability in its Bolt server, allowing unauthorized remote access because the `--address` CLI flag is not correctly plumbed through to the Bolt server config, causing the Bolt listener to always bind to the wildcard address and expose the database with default credentials.
date: "2024-11-02T18:23:00Z"
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

NornicDB versions prior to 1.0.42-hotfix are vulnerable to an improper network binding issue affecting the Bolt server. The vulnerability stems from the `--address` CLI flag (and `NORNICDB_ADDRESS` / `server.host` config key) not being correctly applied to the Bolt server configuration. Consequently, the Bolt listener always binds to the wildcard address (0.0.0.0), irrespective of user-defined configurations. This default behavior exposes the graph database with its default `admin:password`…
