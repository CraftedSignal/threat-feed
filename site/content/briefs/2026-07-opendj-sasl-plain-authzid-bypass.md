---
title: OpenDJ SASL PLAIN Authorization Bypass via Authzid
slug: 2026-07-opendj-sasl-plain-authzid-bypass
description: An authorization bypass vulnerability exists in OpenDJ's SASL PLAIN authentication mechanism, allowing any account with the `proxied-auth` privilege to assume arbitrary non-root directory user identities by bypassing the `mayProxy` ACI scope check when supplying an `authzid`, leading to privilege escalation beyond intended scope.
date: "2026-07-24T21:47:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - authorization-bypass
  - ldap
vendors:
  - OpenIdentityPlatform
products:
  - OpenDJ
  - opendj-server-legacy (<= 5.1.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'Privilege escalation / authorization bypass: a holder of proxied-auth can act as arbitrary directory users beyond the scope intended by the deployment''s proxy ACIs, defeating the ACI-based restriction on which identities may be impersonated.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-p279-2cqp-84jg
---

OpenIdentityPlatform's OpenDJ, specifically versions up to and including 5.1.1, contains a critical authorization bypass vulnerability (GHSA-p279-2cqp-84jg) in its SASL PLAIN authentication mechanism. This flaw, publicly disclosed on 2026-07-24, allows attackers to bypass access control restrictions and achieve privilege escalation. The vulnerability arises when an account with the `proxied-auth` privilege attempts a SASL PLAIN bind and supplies an `authzid` (authorization identity) referencing a *different* user. The `PlainSASLMechanismHandler` incorrectly only verifies the `PROXIED_AUTH` privilege, failing to evaluate the `mayProxy` ACI scope check. This omission allows an attacker to impersonate *any* resolvable non-root identity within the directory, regardless of whether explicit proxy ACI grants exist. This behavior deviates from other proxy paths in OpenDJ, which correctly enforce both privilege and ACI grants. The successful exploitation of this vulnerability leads to unauthorized access and potential compromise of sensitive directory data by defeating the intended granular authorization controls.

## Attack Chain

1. An attacker gains legitimate credentials for an OpenDJ account that holds the `proxied-auth` privilege (e.g., through initial access or misconfiguration).
2. The attacker initiates a SASL PLAIN bind request to the vulnerable OpenDJ server.
3. Within the SASL PLAIN bind, the attacker specifies an `authzid` (authorization identity) parameter, referencing a *different*, target non-root user (e.g., `authzid=u:target_privileged_user`).
4. The OpenDJ server's `PlainSASLMechanismHandler` verifies that the authenticating account possesses the `PROXIED_AUTH` privilege.
5. Crucially, the handler *fails* to perform the `mayProxy` ACI (Access Control Instruction) scope check, which is intended to restrict *which* specific identities can be proxied by the authenticating account.
6. Despite the missing ACI scope check, the authentication succeeds, allowing the attacker to assume the identity and privileges of the `target_privileged_user`.
7. The attacker, now impersonating the target user, performs actions within the directory using the target user's elevated permissions, bypassing the intended ACI-based authorization restrictions.
8. The final objective is privilege escalation and unauthorized access to directory services and data.

## Impact

Successful exploitation of this vulnerability results in privilege escalation and authorization bypass. An attacker holding the `proxied-auth` privilege can act as arbitrary non-root directory users, effectively bypassing the granular access control instructions (ACIs) that would normally limit impersonation capabilities. This completely defeats the intended ACI-based restrictions on which identities may be impersonated, leading to unauthorized access to sensitive directory information or modification of configurations. While the vulnerability does not allow impersonation of the root or Directory Manager accounts, it significantly expands an attacker's reach within the directory environment.

## Recommendation

* Upgrade OpenDJ instances to a patched version beyond 5.1.1 to address GHSA-p279-2cqp-84jg immediately.
* As a temporary workaround, restrict or revoke the `proxied-auth` privilege for any accounts that do not strictly require it, until the affected OpenDJ product can be upgraded.
