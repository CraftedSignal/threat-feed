---
title: CVE-2026-44390 Unbounded Name Compression Denial-of-Service Vulnerability
slug: 2026-05-unbounded-name-compression-dos
description: CVE-2026-44390 is a denial-of-service vulnerability in Microsoft products due to unbounded name compression.
date: "2026-05-21T07:14:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:nlnetlabs:unbound:*:*:*:*:*:*:*:*
tags:
  - dos
  - cve
  - denial-of-service
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-44390
    cvss: 5.3
    epss: 0.00042
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44390
  - CVE-2026-44390
rules:
  - title: Detect CVE-2026-44390 Exploitation Attempt - Suspicious DNS Traffic Volume
    description: Detects CVE-2026-44390 exploitation — High volume of DNS traffic from a single source may indicate an attempt to exhaust resources.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-44390 Exploitation Attempt - DNS Query Size Anomaly
    description: Detects CVE-2026-44390 exploitation — Detects large DNS query sizes indicative of unbounded name compression attempts.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-44390 describes a denial-of-service vulnerability affecting Microsoft products. The vulnerability stems from unbounded name compression, which can lead to excessive resource consumption when processing crafted network packets. Successful exploitation could result in a degradation of service, impacting the availability of affected systems. Defenders should apply relevant patches as soon as possible to mitigate this risk. This vulnerability has the potential to disrupt critical services.

## Attack Chain

Due to the limited information available, a detailed attack chain cannot be fully constructed. However, a general outline based on the nature of the vulnerability is provided below:

1. An attacker crafts a malicious network packet containing a DNS record with unbounded name compression.
2. The attacker sends the crafted packet to a vulnerable Microsoft service that handles DNS requests.
3. The vulnerable service attempts to process the malicious DNS record.
4. The unbounded name compression causes the service to enter a loop or consume excessive memory.
5. Resource exhaustion leads to performance degradation.
6. The service becomes unresponsive or crashes, resulting in a denial-of-service condition.
7. Legitimate users are unable to access the service.

## Impact

Successful exploitation of CVE-2026-44390 leads to a denial-of-service condition, impacting the availability of critical Microsoft services. The extent of the impact depends on the specific service affected and the scale of the attack. Affected organizations may experience disruptions in network services, application downtime, and reduced productivity.

## Recommendation

*   Investigate network traffic for anomalous DNS packets exhibiting characteristics of unbounded name compression (refer to CVE-2026-44390).
*   Deploy the Sigma rules provided to detect potential exploitation attempts.
*   Monitor system resource usage (CPU, memory) for services processing network packets.
