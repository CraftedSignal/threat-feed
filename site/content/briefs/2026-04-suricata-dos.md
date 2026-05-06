---
title: Suricata DoS Vulnerability (CVE-2026-31933)
slug: 2026-04-suricata-dos
description: Specially crafted network traffic can cause Suricata to slow down, leading to a denial-of-service condition in versions prior to 7.0.15 and 8.0.4, as identified by CVE-2026-31933.
date: "2026-04-02T14:16:28Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - dos
  - suricata
  - cve-2026-31933
  - network
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-31933
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31933
  - https://github.com/OISF/suricata/security/advisories/GHSA-hvp5-gpr6-j4gp
  - https://redmine.openinfosecfoundation.org/issues/8272
rules:
  - title: Detect High Packet Rate
    description: Detects a high rate of network packets, potentially indicating a denial-of-service attack
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - suricata
  - title: Detect Multiple Connections from Single Source
    description: Detects a high number of connections originating from a single source IP, indicative of a DoS
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - suricata
rules_count: 2
---

Suricata, a network IDS, IPS, and NSM engine, is susceptible to a denial-of-service vulnerability (CVE-2026-31933) affecting versions prior to 7.0.15 and 8.0.4. This flaw arises from inefficient algorithmic complexity (CWE-407), where specially crafted network traffic can induce a significant slowdown in Suricata's processing, particularly impacting its performance in IDS mode. An attacker can exploit this vulnerability by sending malicious network packets, potentially causing the Suricata instance to become unresponsive or consume excessive resources. The vulnerability was reported and patched by the Open Information Security Foundation (OISF). Organizations using affected Suricata versions are vulnerable to service disruption.

## Attack Chain

1.  The attacker crafts a series of malicious network packets specifically designed to exploit the algorithmic inefficiency in Suricata's packet processing.
2.  The attacker sends the crafted packets to the Suricata instance. This can be achieved through various network protocols and ports monitored by Suricata.
3.  Suricata receives the packets and begins processing them. Due to the inefficient algorithm, processing these packets consumes significantly more resources than legitimate traffic.
4.  As the number of malicious packets increases, Suricata's CPU and memory usage rises dramatically, leading to a performance slowdown.
5.  The slowdown affects Suricata's ability to inspect other network traffic in a timely manner, potentially allowing malicious activity to go undetected.
6.  Eventually, Suricata's performance degrades to the point where it becomes unresponsive, effectively causing a denial-of-service condition.
7.  Legitimate network traffic may be dropped or delayed due to Suricata's inability to process it efficiently.

## Impact

Successful exploitation of CVE-2026-31933 results in a denial-of-service condition, causing Suricata to become unresponsive and hindering its ability to perform network intrusion detection and prevention. The impact includes the potential for undetected malicious activity, delayed or dropped legitimate network traffic, and increased operational overhead for security teams to investigate and remediate the issue. The severity is rated as HIGH with a CVSS v3.1 score of 7.5.

## Recommendation

*   Upgrade Suricata to version 7.0.15 or 8.0.4 or later to patch CVE-2026-31933.
*   Deploy the Sigma rule `DetectHighPacketRate` to identify unusual traffic patterns indicative of a DoS attempt.
*   Monitor Suricata's CPU and memory utilization for unexpected spikes, which could indicate exploitation of this vulnerability.
*   Implement rate limiting or traffic shaping rules on network devices to mitigate the impact of malicious traffic.
