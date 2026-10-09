---
title: Hazelcast Arbitrary Memory Access Vulnerability
slug: 2026-10-hazelcast-memory-access
description: A critical vulnerability in Hazelcast Enterprise and Community Editions allows unauthenticated or low-privileged clients to read arbitrary cluster member memory, potentially enabling remote code execution via memory corruption.
date: "2026-10-09T07:58:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - remote-code-execution
  - hazelcast
  - java
vendors:
  - Hazelcast
products:
  - Hazelcast Enterprise Edition (< 5.7.0, < 5.6.1, < 5.5.10, < 5.4.5)
  - Hazelcast Community Edition (< 5.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A flaw has been found in Hazelcast Enterprise Edition and Community Edition, which would allow a low-privileged malicious client to read arbitrary data in memory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Additionally, such a client may be able to cause one or more cluster members to crash, or in some Enterprise Edition configurations also corrupt memory contents, potentially leading to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-107726
references:
  - https://github.com/advisories/GHSA-6v25-8wq6-xq4j
  - https://support.hazelcast.com/s/article/Security-Advisory-GHSA-6v25-8wq6-xq4j
  - https://docs.hazelcast.com/hazelcast/5.7/secure-cluster/hardening-recommendations
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch all Hazelcast cluster members to the versions listed in the recommendation section.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrading to 5.7.0, 5.6.1, 5.5.10, or 5.4.5.
  mitigation_plan:
    - priority: immediate
      action: Enable Hazelcast client authorization and configure firewall rules to restrict cluster access.
      owner: Security Operations
      addresses: CVE-2026-107726
      evidence: Recommendation provided in the official security advisory.
---

A critical security flaw (CVE-2026-107726) has been identified in both Hazelcast Enterprise and Community Editions, enabling low-privileged clients to access arbitrary memory on cluster members. This access encompasses Java heap memory, off-heap data, and the broader JVM process address space. The vulnerability is particularly severe because it allows for unauthorized data exfiltration and may be exploited to trigger cluster-wide denial-of-service (DoS) conditions. Furthermore, in specific Enterprise Edition configurations, the memory access primitive can be chained to achieve memory corruption, providing an attacker with a path to execute arbitrary code within the context of the Hazelcast process. Organizations running versions below 5.7.0, 5.6.1, 5.5.10, or 5.4.5 are at risk.

## Attack Chain

1. Attacker establishes a connection to the Hazelcast cluster using a low-privileged client identity.
2. Attacker leverages the vulnerability in the Compact serialization or cluster member communication protocol to bypass existing authorization boundaries.
3. Attacker sends specifically crafted requests to the targeted cluster member.
4. The Hazelcast member process parses the malicious input without proper boundary checks.
5. Attacker performs unauthorized reads against JVM heap memory or process address space to exfiltrate sensitive data.
6. Attacker sends malformed data that triggers memory corruption within the JVM process.
7. Attacker executes arbitrary code or crashes the cluster member.

## Impact

Successful exploitation allows attackers to gain unauthorized access to sensitive data stored in-memory within Hazelcast clusters. Given the potential for remote code execution, attackers could gain full control over the compromised Hazelcast cluster nodes, leading to lateral movement, data theft, or service disruption. All sectors utilizing Hazelcast for high-performance in-memory computing are potentially affected.

## Recommendation

Prioritized actions for security and infrastructure teams:
- Patch all instances to the fixed versions (Enterprise 5.7.0, 5.6.1, 5.5.10, 5.4.5; Community 5.7.0) immediately.
- Enable and strictly enforce Hazelcast client authorization to prevent unauthorized access.
- Implement an explicit allowlist for zero-config Compact serialization to restrict potential exploit vectors.
- Restrict network access to cluster nodes via firewall rules to ensure only trusted, hardened clients can communicate with the cluster.
- Disable all unused features to reduce the overall attack surface of the cluster members.
