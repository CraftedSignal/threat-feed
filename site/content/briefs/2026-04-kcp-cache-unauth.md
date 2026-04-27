---
title: Unauthenticated Access to kcp Cache Server
slug: 2026-04-kcp-cache-unauth
description: The kcp cache server is exposed without authentication, allowing unauthorized read access to sensitive data and a race condition for write access that could lead to temporary privilege escalation.
date: "2026-04-08T15:04:22Z"
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

The kcp (Kubernetes Cluster Platform) cache server, responsible for replicating resources, is directly exposed by the root shard without any authentication or authorization checks. This vulnerability allows anyone with network access to the root shard to read replicated resources and potentially write to the cache server, creating a race condition. The lack of authentication in the preHandlerChainMux, specifically identified in `pkg/server/config.go` at line 514-518, causes the cache server to…
