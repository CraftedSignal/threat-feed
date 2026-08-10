---
title: CoreDNS Denial of Service Vulnerabilities
slug: 2026-08-coredns-dos
description: Multiple vulnerabilities in CoreDNS allow remote, unauthenticated attackers to trigger denial of service conditions, potentially disrupting critical name resolution infrastructure.
date: "2026-08-10T13:28:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - network
  - dns
vendors:
  - CoreDNS
products:
  - CoreDNS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in CoreDNS ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2022-0461
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Infrastructure Security
  immediate_actions:
    - action: Inventory all CoreDNS deployments and verify versioning against vendor release notes.
      owner: IT Operations
      due: 48h
      evidence: General vulnerability mitigation guidance for service-level flaws.
  mitigation_plan:
    - priority: immediate
      action: Patch CoreDNS to the latest stable release.
      owner: IT Operations
      addresses: CoreDNS DoS vulnerabilities
      evidence: Standard security advisory remediation
---

CoreDNS is currently affected by multiple identified vulnerabilities that enable a remote, unauthenticated attacker to induce a denial-of-service (DoS) state. CoreDNS serves as a critical component in many container orchestration environments, including Kubernetes, where it handles DNS resolution for cluster services. Successful exploitation can lead to service degradation or complete unavailability of DNS resolution, impacting network communication across dependent applications. Defenders should monitor resource utilization and system stability for CoreDNS deployments to detect anomalous patterns indicative of exploitation attempts, as these vulnerabilities allow for service disruption without requiring authenticated access.

## Impact

Successful exploitation results in the exhaustion of system resources or service instability, leading to denial of service for DNS resolution. This directly impacts the availability of network services, potentially causing widespread outages in containerized environments, internal service discovery failure, and disruption of external traffic routing.

## Recommendation

* Monitor CoreDNS resource usage metrics (CPU and memory consumption) for sudden spikes that may indicate exploitation of denial-of-service vectors.
* Audit CoreDNS logs for high volumes of malformed DNS queries or requests targeting specific plugins.
* Update CoreDNS to the latest version as provided by the distribution or upstream maintainers to address the reported vulnerabilities.
