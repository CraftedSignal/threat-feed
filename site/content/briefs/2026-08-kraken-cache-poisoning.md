---
title: Kraken P2P Cache Poisoning via Insecure Digest Validation
slug: 2026-08-kraken-cache-poisoning
description: Kraken agents are vulnerable to cache poisoning because they rely on CRC32 checksums instead of SHA-256 digests to verify peer-to-peer blobs, enabling malicious peers to inject unauthorized container images.
date: "2026-08-18T18:55:39Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Uber
products:
  - Kraken
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: The Kraken agents are susceptible to cache poisoning, allowing attackers to seed malicious container images that persist within the infrastructure.
    confidence_band: high
cves:
  - id: CVE-2026-75625
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75625
action_plan:
  priority: elevated
  owners:
    - Infrastructure Security
  immediate_actions:
    - action: Review infrastructure logs for anomalous peer-to-peer blob transfer traffic within the Kraken network.
      owner: SOC
      due: 48h
      evidence: CVE-2026-75625 documentation regarding insecure digest validation.
  mitigation_plan:
    - priority: immediate
      action: Restrict Kraken peer-to-peer network access to known, authorized internal hosts.
      owner: IT Operations
      addresses: CVE-2026-75625
      evidence: NVD vulnerability details suggest limiting peer-to-peer exposure.
---

The Kraken peer-to-peer distribution system, developed by Uber, contains a critical security flaw (CVE-2026-75625) where agents fail to verify downloaded blobs against the expected SHA-256 digest before committing data to the content-addressable cache. Instead, the implementation relies solely on CRC32 checksums for piece-level validation. This vulnerability is significant because CRC32 is not cryptographically secure and is susceptible to collision attacks. An attacker positioned on the agent-to-agent communication path, or acting as a malicious peer in the P2P swarm, can inject substituted container image layers or manifest files by crafting them with forged CRC32 checksums. Because the agent fails to perform the final SHA-256 integrity check, the poisoned blobs are committed to the cache and subsequently re-seeded to other hosts in the cluster, leading to unauthorized code execution when those images are pulled and deployed.

## Impact

Successful exploitation allows for widespread cache poisoning across the P2P distribution network. This could lead to the unauthorized execution of arbitrary code within containerized environments, compromising the supply chain and integrity of all services relying on the compromised Kraken cluster for image distribution. Given the nature of container orchestration, this vulnerability can result in lateral movement and host-level compromise across the infrastructure served by the Kraken network.

## Recommendation

Prioritize auditing the internal Kraken network configuration to restrict peer access to trusted, authorized nodes. Monitor inter-agent traffic for anomalous blob-transfer patterns or repeated checksum mismatch alerts that might indicate failed poisoning attempts. Infrastructure teams should evaluate the feasibility of moving to a more secure distribution mechanism or isolating Kraken instances until a patch is applied by the vendor.
