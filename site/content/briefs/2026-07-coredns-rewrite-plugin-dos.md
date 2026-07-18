---
title: CoreDNS Rewrite Plugin Vulnerability Allows Remote Denial of Service
slug: 2026-07-coredns-rewrite-plugin-dos
description: A remote denial-of-service vulnerability (CVE-2026-62299) has been discovered in the CoreDNS rewrite-plugin that can lead to a nil-pointer panic when a downstream plugin returns an EDNS0 response without an OPT record, potentially causing service disruption.
date: "2026-07-18T07:05:02Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - coredns
  - dns
  - vulnerability
  - kubernetes
vendors:
  - CoreDNS Project
products:
  - CoreDNS
  - CoreDNS rewrite-plugin
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote denial-of-service vulnerability (CVE-2026-62299) ... can lead to a nil-pointer panic ... potentially causing service disruption.
    confidence_band: high
cves:
  - id: CVE-2026-62299
    cvss: 5.3
    epss: 0.00301
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62299
---

A critical remote denial-of-service (DoS) vulnerability, identified as CVE-2026-62299, has been reported in the CoreDNS `rewrite-plugin`. This flaw allows a remote attacker to trigger a nil-pointer panic within the CoreDNS server. The vulnerability specifically manifests when the `rewrite-plugin` processes an EDNS0 response that originates from a downstream plugin and lacks an OPT (Option) record. Such a scenario can cause the CoreDNS server to crash, leading to a denial of service for DNS resolution. CoreDNS is widely used in Kubernetes environments, making this vulnerability particularly concerning for containerized applications and services that rely on its stability for service discovery and network communication. Defenders should prioritize patching to prevent significant operational disruption.

## Attack Chain

1. An attacker sends a specially crafted DNS query to a vulnerable CoreDNS server.
2. The CoreDNS server, configured with the `rewrite-plugin`, forwards this query to a downstream DNS plugin.
3. The downstream plugin processes the query and returns an EDNS0 response.
4. Crucially, this EDNS0 response is missing the expected OPT record.
5. The `rewrite-plugin` within CoreDNS attempts to process this malformed EDNS0 response.
6. Due to the absence of the OPT record, the `rewrite-plugin` encounters a nil-pointer, causing an unhandled panic.
7. The CoreDNS process crashes, leading to a denial of service and disrupting DNS resolution for clients.
8. Repeated exploitation can result in sustained service unavailability, impacting dependent applications and services.

## Impact

Successful exploitation of CVE-2026-62299 results in a denial of service (DoS) for the affected CoreDNS instance. This means that the CoreDNS server will crash and stop responding to DNS queries, disrupting service discovery and network connectivity for any applications or systems relying on it. In environments like Kubernetes, where CoreDNS is fundamental for inter-service communication and external name resolution, this can lead to widespread application outages, unavailability of services, and significant operational impact. While specific victim counts are not available, any organization utilizing CoreDNS with the vulnerable rewrite-plugin is at risk.

## Recommendation

* Patch CVE-2026-62299 by updating CoreDNS to the latest version immediately to mitigate the denial-of-service vulnerability.
* Review CoreDNS server logs for crash events or restarts that may indicate exploitation attempts related to CVE-2026-62299.
