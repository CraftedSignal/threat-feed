---
title: etcd Watch API Authorization Bypass via Open-Ended Range Requests
slug: 2026-07-etcd-watch-api-auth-bypass
description: An authorization bypass vulnerability (GHSA-xg4h-6gfc-h4m8) in etcd's Watch API allows an authenticated user with READ permission on a single key to exploit the `clientv3.WithFromKey()` function, gaining unauthorized access to monitor and receive events for all keys lexicographically greater than or equal to their permitted key in clusters with authentication enabled.
date: "2026-07-24T22:44:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - etcd
  - rbac
  - data-collection
vendors:
  - etcd
products:
  - etcd (>= 3.7.0-alpha.0, < 3.7.1)
  - etcd (>= 3.6.0, < 3.6.14)
  - etcd (< 3.5.33)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A user granted READ permission on a single, exact key can use the Watch gRPC API with `clientv3.WithFromKey()`
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: This is an authorization bypass in etcd's RBAC enforcement for the Watch API
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: to receive watch events for every key lexicographically greater than or equal to their permitted key — not just the one key they were granted.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xg4h-6gfc-h4m8
---

A high-severity authorization bypass vulnerability, identified as GHSA-xg4h-6gfc-h4m8, has been discovered in etcd's Watch API, affecting versions prior to 3.5.33, versions 3.6.0 through 3.6.13, and versions 3.7.0-alpha.0 through 3.7.0. This flaw specifically impacts etcd clusters with authentication enabled and allows an authenticated user, even with READ permission limited to a single, exact key, to gain unauthorized access to a significant portion of the etcd keyspace. By leveraging the `clientv3.WithFromKey()` function in a Watch gRPC API request, attackers can monitor and receive events for all keys lexicographically greater than or equal to their permitted key, bypassing RBAC enforcement. This vulnerability grants unauthorized data collection capabilities to users who should have highly restricted access, posing a significant risk to data confidentiality and integrity within etcd deployments.

## Attack Chain

1. An attacker obtains valid authentication credentials for an etcd cluster where RBAC is enabled.
2. The attacker's user account is granted READ permission on a single, specific key within etcd, for example, `/config/app1/secret`.
3. The attacker initiates a Watch gRPC API request to the etcd server using the `clientv3.WithFromKey()` option.
4. The `clientv3.WithFromKey()` option constructs an open-ended watch request, instructing etcd to send events for all keys lexicographically greater than or equal to `/config/app1/secret`.
5. Due to the authorization bypass vulnerability, etcd's RBAC enforcement for the Watch API fails to properly restrict this open-ended range request.
6. The etcd server begins streaming watch events not only for the initially permitted key but also for all subsequent keys in the keyspace (e.g., `/config/app1/user_data`, `/config/app2/settings`, `/production/data`).
7. The attacker receives unauthorized watch events, gaining access to potentially sensitive configuration, secrets, and data stored in the broader etcd keyspace.

## Impact

The successful exploitation of this authorization bypass allows an attacker with limited read permissions to gain unauthorized, broad access to an etcd cluster's keyspace. This can lead to the exposure of sensitive configuration data, secrets, or application-specific information that should otherwise be protected by RBAC. The vulnerability affects any etcd deployment running vulnerable versions with authentication enabled, potentially compromising the confidentiality of critical data. While specific victim counts are not available, any organization using etcd for distributed configuration or service discovery is at risk if they have not applied the patches, especially those with stringent RBAC policies expecting granular access control.

## Recommendation

* Patch etcd instances immediately to versions 3.7.1, 3.6.14, or 3.5.33 to resolve the authorization bypass vulnerability.
* Review all existing READ grants within your etcd RBAC configuration, specifically auditing any user or role with permissions on single keys, as these can be leveraged via the Watch API to gain broader access.
* Restrict network access to etcd's client (gRPC) port via firewall rules or network policies, limiting which hosts can communicate with etcd and reducing the attack surface.
