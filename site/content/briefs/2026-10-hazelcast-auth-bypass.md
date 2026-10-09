---
title: Authorization Bypass in Hazelcast IMap Predicates API
slug: 2026-10-hazelcast-auth-bypass
description: Hazelcast contains an authorization bypass vulnerability in the IMap Predicates API allowing unauthenticated remote code execution on cluster members via malicious predicate input.
date: "2026-10-09T01:58:05Z"
lastmod: "2026-10-09T12:44:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hazelcast:hazelcast:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - java
  - hazelcast
vendors:
  - Hazelcast
products:
  - Hazelcast (< 5.4.5, 5.5.0-5.5.9, 5.6.0)
  - Hazelcast (5.5.0-5.5.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Missing authorization checks in the Predicates API may allow a malicious client to execute arbitrary code on a Hazelcast member.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Missing authorization checks in the Predicates API may allow a malicious client to execute arbitrary code on a Hazelcast member.
    confidence_band: high
cves:
  - id: CVE-2026-107725
references:
  - https://github.com/advisories/GHSA-w294-6q5q-53p8
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3846
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Hazelcast instances to fixed versions (5.7.0, 5.6.1, 5.5.10, 5.4.5)
      owner: IT Operations
      due: 24h
      evidence: Source explicitly lists fixed versions to mitigate CVE-2026-107725.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Hazelcast member ports
      owner: Network Security
      addresses: CVE-2026-107725
      evidence: Restricting network exposure reduces the likelihood of exploitation from unauthorized clients.
updates:
  - at: "2026-10-09T12:44:41Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3846
---

Hazelcast has disclosed a critical authorization bypass vulnerability (CVE-2026-107725) affecting the IMap Predicates API. This vulnerability allows an unauthenticated or unauthorized remote attacker to supply malicious input to the predicate execution engine, which is subsequently processed without proper authorization checks. If successfully exploited, this flaw leads to remote code execution on the targeted Hazelcast member node. The vulnerability impacts Hazelcast Community and Enterprise editions, with specific affected version ranges including everything below 5.4.5, versions 5.5.0 through 5.5.9, and version 5.6.0. Organizations utilizing Hazelcast in exposed network environments are at risk of complete cluster node compromise. There are no available workarounds; remediation requires upgrading to the patched versions: 5.7.0, 5.6.1, 5.5.10, or 5.4.5.

## Impact

Successful exploitation of CVE-2026-107725 results in arbitrary code execution on Hazelcast member nodes. This impact spans all organizations using vulnerable Hazelcast deployments, potentially leading to unauthorized data access, cluster-wide disruption, or lateral movement within the network where the Hazelcast member resides.

## Recommendation

- Upgrade all Hazelcast instances to the patched versions immediately: 5.7.0, 5.6.1, 5.5.10, or 5.4.5.
- Review network access controls to ensure Hazelcast member ports (default 5701) are not exposed to untrusted or public networks.
- Monitor logs for unusual serialized objects or unexpected Java class instantiations originating from client IP addresses.
