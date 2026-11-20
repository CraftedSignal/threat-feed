---
brief_id: brief-2024-01-03-sigred-overflow
event_id: brief-2024-01-03-sigred-overflow
revision: 2
activity_at: "2026-11-20T01:37:27Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:37:27Z"
    checksum: sha256:6d36992ca9912dbc330dc7b9693f7fe9b75f3a9fc36eedf002d6cc207dd9d50c
    summary: exploited:true; KEV CVE-2020-1350
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - references
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Detection of Abnormally Large DNS Responses Indicative of CVE-2020-1350 Exploitation
slug: 2024-01-sigred-overflow
description: This rule detects abnormally large DNS responses indicative of exploitation attempts targeting a known overflow vulnerability (CVE-2020-1350) in Windows DNS servers, potentially leading to Remote Code Execution (RCE) or Denial of Service (DoS).
date: "2024-01-03T12:00:00Z"
lastmod: "2026-11-20T01:36:50Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2021-11-03T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*
tags:
  - sigred
  - dns-server
  - vulnerability
vendors:
  - CrowdStrike
  - Elastic
  - Microsoft
  - ReasonLabs
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - ReasonLabs DNS
  - SentinelOne Cloud Funnel
  - Windows Domain Name System (DNS) Server
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.004
    subtechnique_name: Application or System Exploitation
cves:
  - id: CVE-2020-1350
    cvss: 10
    epss: 0.93808
    kev: true
    kev_status: "true"
references:
  - https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/
  - https://msrc-blog.microsoft.com/2020/07/14/july-2020-security-update-cve-2020-1350-vulnerability-in-windows-domain-name-system-dns-server/
  - https://github.com/maxpl0it/CVE-2020-1350-DoS
  - https://www.elastic.co/security-labs/detection-rules-for-sigred-vulnerability
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_unusual_dns_service_children.toml
rules:
  - title: Abnormally Large DNS Response
    description: Detects DNS responses exceeding 60KB, potentially indicating CVE-2020-1350 exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - lateral_movement
    techniques:
      - T1210
      - T1499.004
    data_sources:
      - network_traffic
      - windows
  - title: DNS Response Size Anomaly
    description: Detects abnormally large DNS responses indicating potential exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - lateral_movement
    techniques:
      - T1210
      - T1499.004
    data_sources:
      - network_connection
      - windows
rules_count: 2
updates:
  - at: "2026-05-12T17:47:04Z"
    level: L2
    summary: added CVE-2020-1350;
    sources:
      - elastic
  - at: "2026-11-20T01:36:50Z"
    level: L3
    summary: exploited:true; KEV CVE-2020-1350
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

This threat brief focuses on the detection of abnormally large DNS responses that may indicate exploitation attempts against CVE-2020-1350, also known as SigRed. This vulnerability affects Windows DNS servers and can lead to Remote Code Execution (RCE) or Denial of Service (DoS) if successfully exploited. The vulnerability resides in how the Windows DNS server parses incoming DNS queries, specifically related to signature records (SIG). An attacker can craft a malicious DNS response that triggers a buffer overflow when processed by the DNS server. This detection rule focuses on identifying network traffic exhibiting abnormally large DNS response sizes, specifically those exceeding 60KB. While some legitimate DNS traffic may approach this size, responses significantly larger are often indicative of exploitation attempts.

## Attack Chain

1.  Attacker sends a specially crafted DNS query to a vulnerable Windows DNS server. The query is designed to trigger the overflow.
2.  The vulnerable DNS server receives the malicious DNS query and attempts to parse it.
3.  Due to the vulnerability (CVE-2020-1350), the DNS server improperly handles the crafted DNS response, leading to a buffer overflow.
4.  The buffer overflow allows the attacker to overwrite critical memory regions within the DNS server process (dns.exe).
5.  The attacker gains control of the DNS server process, potentially executing arbitrary code.
6.  The attacker leverages the compromised DNS server to move laterally within the network, targeting other internal systems. This may involve using the DNS server as a pivot point for further exploitation.
7.  Alternatively, the overflow causes the DNS service to crash, leading to a Denial of Service (DoS) condition.
8.  The attacker achieves their objective: either gaining a foothold for lateral movement or disrupting DNS services.

## Impact

Successful exploitation of CVE-2020-1350 can have severe consequences. An attacker can gain complete control of the DNS server, allowing them to intercept and manipulate DNS traffic, redirect users to malicious websites, or compromise other systems on the network. A successful attack could lead to data exfiltration, ransomware deployment, or other malicious activities. The vulnerability also poses a DoS risk, potentially disrupting critical network services.

## Recommendation

*   Deploy the Sigma rule `Abnormally Large DNS Response` to your SIEM to detect potentially malicious DNS traffic based on response size. Tune the threshold (60000 bytes) based on your environment's legitimate DNS traffic patterns.
*   Investigate any alerts generated by the Sigma rule `Abnormally Large DNS Response` by examining associated Intrusion Detection Signatures (IDS) alerts, and reviewing the `dns.question_type` network fieldset.
*   Apply the latest Microsoft Security Update for CVE-2020-1350 to patch vulnerable Windows DNS servers. If immediate patching is not possible, implement the registry-based workaround provided by Microsoft.
*   Monitor network traffic for unusual activity originating from DNS servers, as successful exploitation can lead to lateral movement.
