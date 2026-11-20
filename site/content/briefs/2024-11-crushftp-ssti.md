---
brief_id: brief-2024-11-14-crushftp-ssti
event_id: brief-2024-11-14-crushftp-ssti
revision: 2
activity_at: "2026-11-20T01:37:27Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:37:27Z"
    checksum: sha256:c30342e2436d74a505694e01da41d813b9f16f596758e23fc8485f0e6ad110c3
    summary: exploited:true; KEV CVE-2024-4040
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - iocs
      - lastmod
      - poc_references
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: CrushFTP Server-Side Template Injection Exploitation
slug: 2024-11-crushftp-ssti
description: Exploitation of CVE-2024-4040, a server-side template injection vulnerability in CrushFTP, allows unauthenticated remote attackers to access files, circumvent authentication, and execute arbitrary commands.
date: "2024-11-14T12:00:00Z"
lastmod: "2026-11-20T01:36:50Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2024-04-24T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=3C972B3F-1DEF-557D-B320-784BD933897E&utm_source=rss&utm_medium=rss
tags:
  - crushftp
  - ssti
  - cve-2024-4040
vendors:
  - CrushFTP
products:
  - CrushFTP < 11
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
cves:
  - id: CVE-2024-4040
    cvss: 9.8
    epss: 0.94426
    kev: true
    kev_status: "true"
references:
  - https://github.com/airbus-cert/CVE-2024-4040
  - https://www.bleepingcomputer.com/news/security/crushftp-warns-users-to-patch-exploited-zero-day-immediately/
  - https://sploitus.com/exploit?id=3C972B3F-1DEF-557D-B320-784BD933897E&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: http://localhost:8080
  - type: url
    value: https://sploitus.com/exploit?id=3C972B3F-1DEF-557D-B320-784BD933897E
  - type: url
    value: https://github.com/Stuub/CVE-2024-4040-SSTI-LFI-PoC
ioc_counts:
  url: 3
rules:
  - title: Detect CrushFTP Server Side Template Injection Attempt
    description: Detects attempts to exploit the CrushFTP server-side template injection vulnerability (CVE-2024-4040) by monitoring for specific patterns in the URI query.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1608.001
    data_sources:
      - webserver
      - linux
  - title: Detect CrushFTP Exploitation via Session Logs
    description: This rule detects potential exploitation of CrushFTP by analyzing session logs for suspicious READ/WROTE actions with specific keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-05-08T09:02:20Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
  - at: "2026-11-20T01:36:50Z"
    level: L3
    summary: exploited:true; KEV CVE-2024-4040
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

The CVE-2024-4040 vulnerability is a server-side template injection flaw affecting CrushFTP versions up to 10.7.1 and 11.1.0. Discovered in April 2024, this vulnerability allows unauthenticated remote attackers to bypass the VFS Sandbox, potentially gaining access to sensitive files and executing arbitrary commands on the affected server. The vulnerability stems from improper handling of template processing, enabling attackers to inject malicious code into server-side templates. Successful exploitation can lead to complete system compromise, data breaches, and disruption of services. Publicly available exploits exist, making this a high-risk vulnerability that requires immediate patching. This activity is detected by analyzing CrushFTP session logs for specific exploitation patterns, focusing on HTTP requests containing malicious template injection payloads.

## Attack Chain

1.  An unauthenticated attacker sends a malicious HTTP request to a CrushFTP server.
2.  The request contains a crafted payload designed to exploit the server-side template injection vulnerability (CVE-2024-4040).
3.  The CrushFTP server processes the malicious payload without proper sanitization, interpreting it as a template directive.
4.  The injected template code allows the attacker to read files outside the VFS sandbox.
5.  The attacker leverages the file read capability to obtain sensitive information such as configuration files or user credentials.
6.  The attacker crafts further requests to execute arbitrary commands on the server.
7.  The attacker uses the executed commands to establish persistence or move laterally within the network.
8.  The attacker achieves complete system compromise, potentially leading to data exfiltration or ransomware deployment.

## Impact

Successful exploitation of CVE-2024-4040 allows attackers to gain unauthorized access to sensitive data, execute arbitrary commands, and potentially compromise the entire CrushFTP server. This can lead to data breaches, service disruption, and financial losses. While specific victim numbers are not available in the provided context, the broad install base of CrushFTP suggests a potentially wide impact across various sectors. The vulnerability is easily exploitable, amplifying the risk.

## Recommendation

*   Apply the security patches for CrushFTP versions up to 10.7.1 and 11.1.0 to address CVE-2024-4040 immediately.
*   Deploy the provided Sigma rules to your SIEM to detect ongoing exploitation attempts by monitoring CrushFTP session logs.
*   Ingest CrushFTP session logs to your SIEM to enable detection of the exploitation attempts (CrushFTP data source).
*   Review and restrict network access to CrushFTP servers to limit the attack surface (network security domain).
