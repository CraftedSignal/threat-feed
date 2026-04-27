---
title: Dgraph Pre-Auth DQL Injection Vulnerability
slug: 2024-10-dgraph-dql-injection
description: A pre-authentication DQL injection vulnerability in Dgraph's `/mutate` endpoint, when ACL is disabled, allows attackers to exfiltrate the entire database by crafting a malicious `cond` field in an upsert mutation.
date: "2024-10-26T12:00:00Z"
severities:
  - critical
tags:
  - dgraph
  - dql-injection
  - injection
  - database-exfiltration
vendors:
  - Dgraph
products:
  - Dgraph
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-mrxx-39g5-ph77
rules:
  - title: Detect Dgraph DQL Injection in Mutation Endpoint
    description: Detects potential DQL injection attempts in the Dgraph /mutate endpoint by looking for suspicious DQL syntax within the 'cond' field of the request body.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 1
---

A critical vulnerability exists in Dgraph, a graph database, allowing unauthenticated attackers to perform full database exfiltration. This flaw resides within the `/mutate` endpoint, specifically when Access Control Lists (ACL) are disabled, which is the default configuration. By injecting malicious DQL queries via a crafted `cond` field in an upsert mutation, attackers can bypass authorization checks and extract sensitive data, including user credentials and secrets. The vulnerability stems…
