---
brief_id: brief-2026-06-09-veeam-rce-cve-2026-44963
event_id: brief-2026-06-09-veeam-rce-cve-2026-44963
revision: 2
activity_at: "2026-11-20T04:33:02Z"
revision_history:
  - revision: 2
    at: "2026-11-20T04:33:02Z"
    checksum: sha256:a93a4012b07a5b96d502fa1e96ce884698dd8b8b8c5ebe299c1db1b235ab66d3
    summary: poc_available
    changed_fields:
      - cpes
      - cve_verification
      - cves
      - has_poc
      - iocs
      - lastmod
      - poc_references
      - references
      - rules
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOCKERJML-CVE-2026-44963-VEEAM-CHECKER&utm_source=rss&utm_medium=rss
title: Vulnerability in Veeam Backup & Replication Allowing Remote Code Execution (CVE-2026-44963)
slug: 2026-06-veeam-rce
description: A critical remote code execution vulnerability, tracked as CVE-2026-44963, has been discovered in Veeam Backup & Replication versions prior to 12.3.2.4854, which could allow an unauthenticated attacker to execute arbitrary code on affected systems, leading to full compromise of the backup infrastructure and potential data exfiltration or destruction.
date: "2026-06-14T09:09:13Z"
lastmod: "2026-11-20T04:32:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:veeam:backup_replication_12_3_2_4854:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOCKERJML-CVE-2026-44963-VEEAM-CHECKER&utm_source=rss&utm_medium=rss
tags:
  - remote-code-execution
  - vulnerability
  - veeam
  - backup-replication
  - data-exfiltration
  - data-destruction
  - windows
vendors:
  - Veeam
products:
  - Veeam Backup & Replication < 12.3.2.4854
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
cve_verification:
  CVE-2026-44963:
    status: verified
    source: nvd
    checked_at: 2026-11-20T04:32:48.179056553Z
cves:
  - id: CVE-2026-44963
    epss: 0.02351
    kev_status: "false"
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0712/
  - https://www.veeam.com/kb4869
  - https://www.cve.org/CVERecord?id=CVE-2026-44963
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOCKERJML-CVE-2026-44963-VEEAM-CHECKER&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://www.veeam.com/kb4869
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-44963
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-44963 Exploitation - PowerShell Encoded Command from Veeam Service
    description: Detects suspicious PowerShell execution with encoded commands spawned as a child process of a Veeam Backup & Replication service, indicative of post-exploitation activity after CVE-2026-44963 RCE.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
updates:
  - at: "2026-11-20T04:32:48Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOCKERJML-CVE-2026-44963-VEEAM-CHECKER&utm_source=rss&utm_medium=rss
---

## Overview

CERT-FR has published an advisory regarding a critical remote code execution (RCE) vulnerability, CVE-2026-44963, affecting Veeam Backup & Replication software. This flaw impacts all versions prior to 12.3.2.4854. An unauthenticated attacker can exploit this vulnerability to execute arbitrary code on the underlying operating system where Veeam Backup & Replication is installed. The exploitation of such a vulnerability on a backup server is particularly severe, as these systems often have extensive network access and contain highly sensitive data, including backups of critical organizational assets. Organizations using vulnerable versions are strongly advised to apply the security patch referenced in Veeam's security bulletin kb4869 without delay to prevent potential compromise.

## Attack Chain

1.  An unauthenticated attacker identifies a public-facing or internally accessible Veeam Backup & Replication server running a vulnerable version (prior to 12.3.2.4854).
2.  The attacker crafts a specialized malicious request designed to exploit the specific vulnerability (CVE-2026-44963) within the Veeam Backup & Replication service.
3.  The crafted request is sent to the vulnerable Veeam Backup & Replication service, often targeting a specific network endpoint or component.
4.  The vulnerable Veeam service processes the malicious input, leading to a bypass of security controls and successful injection of attacker-controlled code.
5.  Arbitrary code, specified by the attacker, is executed on the server running Veeam Backup & Replication, typically under the context of the compromised Veeam service.
6.  The attacker gains control over the compromised server, potentially with elevated privileges, enabling them to navigate the internal network.
7.  The attacker leverages access to perform actions such as exfiltrating sensitive backup data, encrypting backups for ransomware deployment, or establishing persistent access within the environment.

## Impact

Successful exploitation of CVE-2026-44963 leads to full remote code execution on the server hosting Veeam Backup & Replication. This results in the complete compromise of the backup infrastructure, enabling attackers to gain unauthorized access to all backed-up data, potentially delete or encrypt it, and establish a foothold for further lateral movement within the network. The highly sensitive nature of backup environments means an attack could lead to severe data loss, exfiltration of critical business information, significant operational disruption, and regulatory non-compliance. While specific victim counts are not available, the widespread use of Veeam Backup & Replication suggests a broad potential impact across various sectors.

## Recommendation

*   Apply the security update provided by Veeam (kb4869) immediately to patch CVE-2026-44963 on all affected Veeam Backup & Replication servers.
*   Deploy the provided Sigma rules to your SIEM solution to detect potential exploitation attempts and post-exploitation activities.
*   Ensure Sysmon process creation logging is enabled on all servers running Veeam Backup & Replication to capture data for the provided Sigma rules.
*   Monitor network connections originating from Veeam Backup & Replication services for suspicious outbound traffic not aligned with normal backup operations, as highlighted by the network connection rule.
