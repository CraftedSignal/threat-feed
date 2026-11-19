---
brief_id: brief-2026-05-trend-micro-vulns
event_id: brief-2026-05-trend-micro-vulns
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:383ab26e025c82621aed3ed1d375d2ff9b6de279bee6d89d02c5f1618854adc4
    summary: exploited:true; KEV CVE-2026-34926; KEV CVE-2025-54948; KEV CVE-2022-40139; KEV CVE-2023-41179
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Multiple Vulnerabilities in Trend Micro Products Including TrendAI Apex One
slug: 2026-05-trend-micro-vulns
description: Multiple vulnerabilities exist in Trend Micro products, including TrendAI Apex One, potentially allowing authenticated attackers to tamper with files, distribute malicious code, or escalate privileges; CVE-2026-34926 is being actively exploited.
date: "2026-05-21T06:58:11Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2022-09-15T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:trendmicro:apex_one:-:*:*:*:saas:*:*:*
  - cpe:2.3:a:trendmicro:apex_one:2019:*:*:*:*:*:*:*
  - cpe:2.3:a:trendmicro:apex_one:2019:*:*:*:-:*:*:*
  - cpe:2.3:a:trendmicro:apex_one:2019:*:*:*:on-premises:windows:*:*
  - cpe:2.3:a:trendmicro:apex_one:2019:*:*:*:saas:*:*:*
  - cpe:2.3:a:trendmicro:worry-free_business_security:10.0:sp1:*:*:*:*:*:*
  - cpe:2.3:a:trendmicro:worry-free_business_security_services:-:*:*:*:saas:*:*:*
has_poc: true
tags:
  - vulnerability
  - apex-one
  - trend-micro
  - path-traversal
vendors:
  - Trend Micro
  - TrendAI
products:
  - Apex One
  - Apex One (on-premise version)
  - Trend Micro Apex One as a Service
  - TrendAI Apex One (On Premise)
  - TrendAI Vision One Endpoint Security - Standard Endpoint Protection
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34926
    cvss: 6.7
    kev: true
    kev_status: "true"
  - id: CVE-2025-54948
    cvss: 9.4
    epss: 0.08821
    kev: true
    kev_status: "true"
  - id: CVE-2022-40139
    cvss: 7.2
    epss: 0.08915
    kev: true
    kev_status: "true"
  - id: CVE-2023-41179
    cvss: 7.2
    epss: 0.0253
    kev: true
    kev_status: "true"
references:
  - https://www.jpcert.or.jp/english/at/2026/at260014.html
  - https://success.trendmicro.com/ja-JP/solution/KA-0022974
  - https://jvn.jp/en/vu/JVNVU90583059
  - https://www.securityweek.com/trendai-patches-apex-one-zero-day-exploited-in-the-wild/
  - https://www.bleepingcomputer.com/news/security/trend-micro-warns-of-apex-one-zero-day-exploited-in-attacks/
iocs:
  - type: email
    value: ew-info@jpcert.or.jp
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious File Creation in Trend Micro Directories
    description: Detects suspicious file creation in Trend Micro installation directories, potentially indicating exploitation of CVE-2026-34926 or similar vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Trend Micro Apex One Service Restart via Command Line
    description: Detects attempts to restart Trend Micro Apex One services via the command line, which can be an indicator of malicious activity or unauthorized changes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-05-22T08:20:50Z"
    level: L2
    summary: added CVE-2026-34926
    sources:
      - securityweek
  - at: "2026-05-22T13:40:40Z"
    level: L2
    summary: poc_available; added CVE-2022-40139 +2
    sources:
      - bleepingcomputer
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-34926; KEV CVE-2025-54948; KEV CVE-2022-40139; KEV CVE-2023-41179
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

On May 21, 2026, Trend Micro disclosed multiple vulnerabilities affecting TrendAI Apex One (On Premise), Trend Micro Apex One as a Service, and TrendAI Vision One Endpoint Security - Standard Endpoint Protection. Successful exploitation could allow an authenticated attacker to tamper with arbitrary files on the server, potentially leading to the distribution of crafted code to the security agent or privilege escalation. Trend Micro has reported that CVE-2026-34926, a relative path traversal vulnerability within TrendAI Apex One (On Premise), is currently being exploited in the wild. Given the active exploitation of CVE-2026-34926, immediate patching is strongly recommended for all affected products.

## Attack Chain

1. Authenticated attacker gains initial access to the TrendAI Apex One server.
2. Attacker exploits CVE-2026-34926, a relative path traversal vulnerability, to write arbitrary files to the server.
3. The attacker uses the path traversal to overwrite legitimate Trend Micro files with malicious code.
4. The malicious code is designed to be distributed to security agents managed by the compromised Apex One server.
5. Apex One server distributes the tampered files to managed endpoints as part of a routine update or configuration change.
6. Endpoints execute the malicious code, granting the attacker further access or control over the compromised systems.
7. The attacker escalates privileges on the compromised endpoint.
8. The attacker uses the compromised endpoint as a pivot point to access other internal systems or data.

## Impact

Successful exploitation of these vulnerabilities could lead to widespread compromise of endpoints managed by the affected Trend Micro products. Given that CVE-2026-34926 is being actively exploited, the impact could include data theft, ransomware deployment, or disruption of critical business services. The number of victims and specific sectors targeted are currently unknown, but the potential for significant damage exists due to the widespread use of Trend Micro endpoint security products.

## Recommendation

*   Apply the appropriate patch for TrendAI Apex One (On Premise), Trend Micro Apex One as a Service, and TrendAI Vision One Endpoint Security - Standard Endpoint Protection as outlined in the Trend Micro advisory to remediate the vulnerabilities, with particular urgency for TrendAI Apex One (On Premise) due to active exploitation (CVE-2026-34926).
*   Deploy the Sigma rule `Detect Suspicious File Creation in Trend Micro Directories` to identify potential exploitation attempts involving malicious file writes.
*   Monitor network traffic for suspicious outbound connections originating from Trend Micro managed endpoints after patch deployment, using network connection logs, to detect any potential compromise.
*   Investigate any alerts generated by the `Detect Suspicious File Creation in Trend Micro Directories` rule to determine the scope and impact of any potential compromise.
