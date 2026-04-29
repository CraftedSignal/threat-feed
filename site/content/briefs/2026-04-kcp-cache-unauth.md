---
title: Unauthenticated Access to kcp Cache Server
slug: 2026-04-kcp-cache-unauth
description: The kcp cache server is exposed without authentication, allowing unauthorized read access to sensitive data and a race condition for write access that could lead to temporary privilege escalation.
date: "2026-04-08T15:04:22Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - kcp
  - kubernetes
  - cache
  - authentication
  - authorization
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-3j3q-wp9x-585p
rules:
  - title: Detect Access to Unprotected KCP Cache API
    description: Detects unauthorized access attempts to the KCP cache API endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect Attempts to POST data to KCP Cache API
    description: Detects POST attempts to the KCP cache API which might indicate an attempt to inject malicious RBAC rules.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The kcp (Kubernetes Cluster Platform) cache server, responsible for replicating resources, is directly exposed by the root shard without any authentication or authorization checks. This vulnerability allows anyone with network access to the root shard to read replicated resources and potentially write to the cache server, creating a race condition. The lack of authentication in the preHandlerChainMux, specifically identified in `pkg/server/config.go` at line 514-518, causes the cache server to be proxied before authentication or authorization can take place. This impacts kcp versions prior to v0.29.3 and between v0.30.0 and v0.30.3. This vulnerability allows unauthorized access to sensitive information, including RBAC rules, cluster topology, API surfaces, admission control policies, and tenancy configurations.

## Attack Chain

1. Attacker gains network access to the kcp root shard, typically through exposed ports or external URLs.
2. Attacker crafts an HTTP request targeting the `/services/cache/*` endpoint without any authentication headers.
3. The request bypasses authentication and authorization checks due to the flawed preHandlerChainMux configuration.
4. The attacker reads replicated resources from the cache, such as clusterroles, clusterrolebindings, logicalclusters, apiexports, and validatingwebhookconfigurations.
5. (Optional) The attacker attempts to inject a malicious ClusterRole and ClusterRoleBinding via a POST request to the cache server.
6. The cache etcd watch fires, notifying the authorization informer and replication controller in parallel.
7. The authorization informer updates its in-memory store, briefly granting the attacker the injected RBAC rules.
8. The replication controller eventually reconciles and deletes the injected object, but a small window of opportunity exists for privilege escalation.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to critical cluster information, potentially exposing RBAC configurations, API endpoints, and internal infrastructure details. An attacker can read replicated resources, including cluster roles, cluster role bindings, logical clusters, shards, API exports, API resource schemas, mutating webhook configurations, validating webhook configurations, validating admission policies, and workspace types. While injected objects are quickly cleaned up, a brief race condition allows for temporary privilege escalation. This affects kcp deployments where the root shard is network-reachable by untrusted clients, including Helm chart deployments, Operator deployments with external URLs set, and deployments with a reachable --shard-external-url.

## Recommendation

*   Implement network-level access control to restrict access to the `/services/cache/*` paths at the load balancer, reverse proxy, or firewall level as described in the **Workarounds** section of the advisory.
*   Deploy the cache server separately with its own kubeconfig (`--cache-server-kubeconfig`) and restrict network access to it, mitigating direct exposure to the root shard as per the **Workarounds** section.
*   Upgrade to kcp version v0.29.3 or v0.30.3 or later to patch the vulnerability as per **CVE-2026-39429**.
