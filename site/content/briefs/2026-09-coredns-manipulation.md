---
title: CoreDNS DNS Record Manipulation Vulnerability
slug: 2026-09-coredns-manipulation
description: A vulnerability in CoreDNS allows a remote, unauthenticated attacker to manipulate DNS records, potentially enabling traffic redirection or DNS cache poisoning.
date: "2026-09-07T13:34:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:coredns:coredns:*:*:*:*:*:*:*:*
tags:
  - dns
  - vulnerability
  - coredns
vendors:
  - CNCF
products:
  - CoreDNS
cves:
  - id: CVE-2024-45337
    cvss: 9.1
    epss: 0.03153
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3198
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Identify and patch all instances of CoreDNS to the latest secure version addressing CVE-2024-45337
      owner: IT Operations
      addresses: CVE-2024-45337
      evidence: Source advisory identifies vulnerability in CoreDNS
  gaps:
    - Need to determine internal inventory of CoreDNS versions
---

CoreDNS, a flexible, extensible DNS server widely used in Kubernetes environments, contains a vulnerability (CVE-2024-45337) that allows remote, unauthenticated attackers to manipulate DNS records. This flaw impacts the integrity of DNS resolutions performed by the server. By exploiting this weakness, an attacker could potentially inject malicious DNS responses, leading to traffic redirection to attacker-controlled infrastructure or performing DNS cache poisoning attacks. Organizations relying on CoreDNS for internal name resolution or as a cluster-internal DNS provider should prioritize investigating their deployment configurations and monitoring for anomalous DNS traffic patterns that deviate from expected internal service resolution behavior.

## Impact

Successful exploitation of this vulnerability allows an attacker to compromise the integrity of DNS lookups within the affected environment. This could lead to the redirection of service traffic, enabling interception of sensitive data, service disruption, or the facilitation of further exploitation steps against applications relying on DNS for connectivity. The scope of impact is highly dependent on the architecture of the DNS infrastructure, affecting any environment that utilizes CoreDNS for recursive or authoritative resolution.

## Recommendation

Prioritize the identification and patching of all CoreDNS deployments within the environment, ensuring versions susceptible to CVE-2024-45337 are upgraded to the latest secure release. Because this vulnerability involves manipulation of DNS records, detection engineering teams should implement monitoring for unexpected outbound DNS requests or discrepancies in resolution patterns from core network infrastructure.
