---
title: Unauthenticated Disk Replica Eviction in Mooncake Store
slug: 2026-10-mooncake-store-missing-auth
description: Mooncake Store versions up to 0.3.13.post1 are vulnerable to a missing authorization flaw in the coro_rpc master port that allows unauthenticated attackers to trigger unauthorized object deletion via replica eviction.
date: "2026-10-06T14:56:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mooncake:mooncake_store:*:*:*:*:*:*:*:*
vendors:
  - Mooncake
products:
  - Mooncake Store (<= 0.3.13.post1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: By targeting the coro_rpc master port, an attacker can evict DISK replicas across all tenants, deleting objects whose only remaining replica is on disk.
    confidence_band: high
cves:
  - id: CVE-2026-106040
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106040
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block unauthorized network access to the coro_rpc master port
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated attackers reaching the coro_rpc master port can evict DISK replicas
  mitigation_plan:
    - priority: immediate
      action: Restrict coro_rpc master port access via network ACLs
      owner: IT Operations
      addresses: CVE-2026-106040
      evidence: CVE-2026-106040 vulnerability analysis
---

Mooncake Store versions up to and including 0.3.13.post1 contain a missing authorization vulnerability (CVE-2026-106040). This flaw resides within the coro_rpc master port functionality, which fails to enforce access control checks for sensitive operations. Unauthenticated remote attackers can connect to the exposed master port and invoke the EvictDiskReplica or BatchEvictDiskReplica functions. By successfully executing these functions, an attacker can force the system to evict disk replicas across all tenants. This vulnerability is significant because if a disk replica is the sole remaining copy of an object, invoking these functions results in permanent data loss for those objects. Defenders should restrict network access to the coro_rpc master port to trusted management subnets and upgrade to a patched version once available.

## Impact

Successful exploitation allows unauthenticated attackers to perform unauthorized administrative actions against the storage infrastructure. The primary impact is the potential for permanent data loss across all tenants if an attacker targets objects where the disk replica is the unique surviving copy, leading to widespread service degradation or data destruction.

## Recommendation

* Restrict network access to the coro_rpc master port to only authorized management IPs at the network firewall layer.
* Audit access logs for unexpected or unauthorized connections originating from non-management subnets targeting the coro_rpc service.
* Monitor for abnormally high volumes of calls to EvictDiskReplica or BatchEvictDiskReplica functions, as these may indicate malicious activity or system abuse.
* Update Mooncake Store to a version greater than 0.3.13.post1 as soon as a security update is released by the vendor to address the missing authorization logic.
