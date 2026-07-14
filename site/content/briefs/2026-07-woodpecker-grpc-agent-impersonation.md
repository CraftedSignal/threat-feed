---
title: Woodpecker CI gRPC Vulnerability Allows Cross-Tenant Agent Impersonation (CVE-2026-50141)
slug: 2026-07-woodpecker-grpc-agent-impersonation
description: A high-severity vulnerability (CVE-2026-50141) in Woodpecker CI's gRPC layer allowed any authenticated agent to impersonate any other agent on the same server by injecting a forged `agent_id` into gRPC metadata, leading to potential privilege escalation and unauthorized access within CI/CD pipelines.
date: "2026-07-14T19:18:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - grpc
  - ci-cd
vendors:
  - Woodpecker CI
products:
  - Woodpecker CI v3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in Woodpecker CI's gRPC layer allowed any authenticated agent to impersonate any other agent on the same server... The server correctly verified the JWT token but then discarded the verified agent identity in favor of the client-supplied value.
    confidence_band: high
cves:
  - id: CVE-2026-50141
    epss: 0.00246
references:
  - https://github.com/advisories/GHSA-g7mm-9vx7-jm7h
  - https://github.com/woodpecker-ci/woodpecker/pull/6567
  - https://github.com/woodpecker-ci/woodpecker/pull/6569
  - https://github.com/woodpecker-ci/woodpecker/issues/6541
  - https://github.com/woodpecker-ci/woodpecker-security/issues/21
---

A significant security flaw, tracked as CVE-2026-50141, was discovered in the gRPC communication layer of Woodpecker CI, a continuous integration platform. This vulnerability enabled any authenticated Woodpecker agent to effectively impersonate another agent residing on the same server. The core issue stemmed from the server's handling of `agent_id` metadata within gRPC requests. While the server correctly validated the JSON Web Token (JWT) provided by the client, it erroneously prioritized a client-supplied `agent_id` value over the verified identity derived from the JWT. This design flaw meant that a malicious or compromised agent could forge its identity, bypassing security controls and gaining unauthorized access to resources or executing actions typically reserved for the impersonated agent. The vulnerability impacts Woodpecker CI v3 versions, specifically from 3.0.0 up to, but not including, 3.14.1. This could lead to severe consequences for organizations using affected versions, including unauthorized code execution, data exfiltration, or disruption of CI/CD pipelines.

## Attack Chain

1. An attacker gains authenticated access as any legitimate, potentially low-privileged, Woodpecker agent to the CI server.
2. The attacker crafts a gRPC request, intending to perform an action or access resources.
3. Within the gRPC request metadata, the attacker injects a forged `agent_id` value corresponding to a target agent they wish to impersonate.
4. The malicious gRPC request is sent to the Woodpecker CI server.
5. The server receives the request and correctly verifies the JWT token, confirming the attacker's original, legitimate agent identity.
6. During subsequent processing, the server *incorrectly* discards the verified agent identity from the JWT.
7. The server then prioritizes and accepts the forged `agent_id` supplied in the gRPC metadata by the attacker.
8. The server executes the requested action or grants access to resources as if the request originated from the impersonated target agent, leading to unauthorized operations or privilege escalation.

## Impact

Successful exploitation of CVE-2026-50141 allows an attacker to achieve cross-tenant agent impersonation within a Woodpecker CI environment. This can lead to significant unauthorized access and control over CI/CD pipelines, potentially enabling malicious actors to trigger builds, deploy unauthorized code, access sensitive repositories, or exfiltrate intellectual property. Organizations using affected versions of Woodpecker CI (v3.0.0 through v3.14.0) are at risk of severe operational disruption and data breaches. While no specific victim count or targeted sector is provided, any organization leveraging Woodpecker CI for their development workflows is a potential target.

## Recommendation

* **Patch CVE-2026-50141 immediately**: Upgrade Woodpecker CI v3 to version 3.14.1 or later to apply the necessary security patches mentioned in the references.
* **Implement workarounds if patching is not immediate**: As a temporary mitigation, disable organization agents by setting `WOODPECKER_DISABLE_USER_AGENT_REGISTRATION=true` and delete any existing organization agents.
* **Review logs for unusual gRPC activity**: While specific detection rules are challenging for this vulnerability, monitor Woodpecker CI server logs for any anomalies in agent behavior or unexpected actions attributed to specific agents, particularly after an agent has been authenticated.
