---
title: Hard-coded Replication Secret in Central Dogma Enables Cluster Takeover
slug: 2026-09-central-dogma-secret
description: Central Dogma uses a hard-coded ZooKeeper replication secret that allows unauthenticated network actors to access configuration logs, perform session forgery, and gain cluster-wide command execution.
date: "2026-09-12T00:57:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - configuration-vulnerability
  - hardcoded-credential
  - central-dogma
  - zookeeper
vendors:
  - LINE
products:
  - Central Dogma
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attacker reaches the quorum port of any Central Dogma replica from a co-located workload (same K8s namespace, same VLAN, etc.).
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials in Files'
    evidence: private static final String DEFAULT_SECRET = "ch4n63m3";
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552.003
    technique_name: 'Unsecured Credentials: Credentials in Configuration File'
    evidence: The constant is in OSS source on GitHub and is discoverable via code search in seconds.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2j95-gqxf-v3vg
action_plan:
  priority: immediate_escalation
  owners:
    - Infrastructure Engineering
    - Security Operations
  immediate_actions:
    - action: Audit all Central Dogma configuration files for missing 'replication.secret' fields.
      owner: Infrastructure Engineering
      due: 24h
      evidence: Source confirms 'replication.secret' is the primary mitigation.
  mitigation_plan:
    - priority: immediate
      action: Define a high-entropy secret in 'replication.secret' and restrict network access to quorum ports.
      owner: Infrastructure Engineering
      addresses: Hard-coded credential vulnerability
      evidence: Advisory mitigation section
---

Central Dogma clusters, when configured for high availability using ZooKeeper replication, are vulnerable to unauthorized access due to a hard-coded default secret. The `ZooKeeperReplicationConfig.secret()` method silently defaults to the string "ch4n63m3" if no `replication.secret` is provided in the configuration. This secret is used for SASL authentication across both the local client-facing ZooKeeper port and the inter-replica quorum ports. Because the default value is publicly visible in the open-source repository and no warning is issued when it is utilized, production clusters are susceptible to compromise if they rely on default configurations. An attacker with network reachability to the ZooKeeper ports can authenticate as the 'super' user, enabling full read/write access to the internal replication logs that govern the entire Central Dogma cluster.

## Attack Chain

1. Attacker identifies a Central Dogma cluster with high-availability replication enabled but without a customized `replication.secret`.
2. Attacker establishes network connectivity to a ZooKeeper quorum port (exposed on the inter-replica network) or utilizes local access to reach the loopback-bound client port.
3. Attacker initiates a SASL DIGEST-MD5 handshake using the username 'super' and the publicly known default secret 'ch4n63m3'.
4. Authentication succeeds, allowing the attacker to join the ZK ensemble as a learner or authenticate as a super-user client.
5. Attacker enumerates existing configuration logs via the ZK znodes `/dogma/logs` and `/dogma/log_blocks`.
6. Attacker monitors replication in real-time to intercept sensitive configuration secrets or session master keys.
7. Attacker optionally injects forged `ReplicationLog` entries to be replayed by legitimate replicas, leading to unauthorized command execution such as `PURGE_PROJECT` or `ROTATE_SESSION_MASTER_KEY` across all cluster nodes.

## Impact

Successful exploitation results in a complete cluster takeover. An attacker can read the entire history of configuration changes, including pushed file contents and sensitive encryption keys. By injecting forged logs, an attacker can execute arbitrary commands across all replicas, permanently delete projects, or re-encrypt data with attacker-controlled keys. The blast radius covers all services and microservices that consume data from the compromised Central Dogma instance.

## Recommendation

Prioritize immediate audit of Central Dogma configurations across all production and staging environments to ensure a unique, complex `replication.secret` is explicitly defined. Implement network segmentation and firewall rules to strictly limit access to the ZooKeeper quorum ports (defaulting to the ports configured in `replication.servers`) to known peer IP addresses only. Upgrade to a patched version that removes the silent fallback mechanism and enforces explicit secret definition.
