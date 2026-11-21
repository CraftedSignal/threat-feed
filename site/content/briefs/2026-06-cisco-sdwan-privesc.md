---
brief_id: brief-2026-06-cisco-sdwan-privesc
event_id: brief-2026-06-cisco-sdwan-privesc
revision: 3
activity_at: "2026-11-21T14:10:50Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:316dba4012f10892a448ccea08deb4e916ae7bd7560cd5627e113b0067b31977
    summary: exploited:true; KEV CVE-2026-20245
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - revision: 3
    at: "2026-11-21T14:10:50Z"
    checksum: sha256:5409977fdbf4f2eca34aaf7783eb3d8aa7ae868c1c606688ad7ad97e15b455d3
    summary: poc_available
    changed_fields:
      - cve_verification
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - poc_references
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FEVAR54-CVE-2026-20245---CISCO-SD-WAN-PRIVILEGE-ESCALATION-EXPLOIT&utm_source=rss&utm_medium=rss
title: 'CVE-2026-20245: Cisco Catalyst SD-WAN Manager Privilege Escalation via Crafted File'
slug: 2026-06-cisco-sdwan-privesc
description: An improper encoding or escaping of output vulnerability, tracked as CVE-2026-20245, in Cisco Catalyst SD-WAN Manager allows an authenticated, local attacker to execute arbitrary commands as root by supplying a specially crafted file to the system, leading to privilege escalation and full system compromise.
date: "2026-06-14T08:54:44Z"
lastmod: "2026-11-21T14:10:23Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-06-14T08:54:44Z"
  confidence: high
cpes:
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:20.12.7:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vsmart_controller:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vsmart_controller:20.12.7:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FEVAR54-CVE-2026-20245---CISCO-SD-WAN-PRIVILEGE-ESCALATION-EXPLOIT&utm_source=rss&utm_medium=rss
tags:
  - privilege-escalation
  - rce
  - network-device
  - cisco
  - linux
vendors:
  - Cisco
products:
  - Catalyst SD-WAN Manager
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cve_verification:
  CVE-2026-20245:
    status: verified
    source: nvd
    checked_at: 2026-11-21T14:10:23.427542883Z
cves:
  - id: CVE-2026-20245
    cvss: 7.8
    epss: 0.25323
    kev: true
    kev_status: "true"
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-20245
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20245
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FEVAR54-CVE-2026-20245---CISCO-SD-WAN-PRIVILEGE-ESCALATION-EXPLOIT&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-20245 exploitation - SD-WAN Manager Spawning Shell
    description: Detects CVE-2026-20245 exploitation - identifies suspicious child processes (shells or common command execution binaries) spawned by the Cisco Catalyst SD-WAN Manager process, indicating arbitrary command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detects CVE-2026-20245 exploitation - SD-WAN Manager Creating Suspicious Executables
    description: Detects CVE-2026-20245 exploitation - identifies the Cisco Catalyst SD-WAN Manager process creating executable files (scripts or binaries) in unusual or temporary directories, potentially for staging further attacks.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036
      - T1059
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-20245
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - at: "2026-11-21T14:10:23Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FEVAR54-CVE-2026-20245---CISCO-SD-WAN-PRIVILEGE-ESCALATION-EXPLOIT&utm_source=rss&utm_medium=rss
---

## Overview

Cisco Catalyst SD-WAN Manager (formerly SD-WAN vManage) is affected by CVE-2026-20245, a critical improper encoding or escaping of output vulnerability. This flaw enables an authenticated attacker with local access to the system to achieve root-level arbitrary command execution. By supplying a specially crafted file to the SD-WAN Manager, the attacker can exploit the vulnerability to bypass security controls and gain full control over the appliance. The vulnerability's presence on the CISA Known Exploited Vulnerabilities (KEV) catalog underscores its severe risk and indicates active exploitation, making immediate patching and monitoring crucial for organizations utilizing Cisco Catalyst SD-WAN solutions.

## Attack Chain

1.  **Initial Access**: An attacker gains authenticated local access to the Cisco Catalyst SD-WAN Manager's web interface or command-line interface, typically through compromised credentials or other local vulnerabilities.
2.  **Payload Crafting**: The attacker develops a malicious file (e.g., a configuration file, script, or data file) that contains embedded arbitrary commands, specifically crafted to exploit the improper encoding/escaping vulnerability.
3.  **Malicious File Submission**: The crafted file is uploaded or provided to the Cisco Catalyst SD-WAN Manager system through an affected feature or interface that processes user-supplied files.
4.  **Vulnerability Trigger**: When the SD-WAN Manager processes the supplied file, the improper encoding or escaping of output leads the system to misinterpret benign data as executable commands.
5.  **Command Execution**: The embedded arbitrary commands within the crafted file are executed by the vulnerable SD-WAN Manager process on the underlying Linux operating system.
6.  **Privilege Escalation**: The executed commands run with root privileges, granting the attacker complete control over the SD-WAN Manager appliance.
7.  **System Compromise**: With root access, the attacker can perform actions such as modifying network configurations, exfiltrating sensitive network data, establishing persistence, or disrupting network operations managed by the SD-WAN solution.

## Impact

Successful exploitation of CVE-2026-20245 grants an attacker root-level access to the Cisco Catalyst SD-WAN Manager. This level of access enables complete control over the network management system, potentially leading to widespread network disruption, unauthorized access to network resources, data exfiltration from the managed network, and the deployment of further malicious tools or backdoors. Compromise of an SD-WAN manager can have a cascading effect across an organization's entire wide-area network, impacting business continuity and data confidentiality.

## Recommendation

*   Immediately apply patches or mitigations provided by Cisco for CVE-2026-20245 as per the Cisco Security Advisory (cisco-sa-sdwan-privesc-4uxFrdzx).
*   Deploy the Sigma rules in this brief to your SIEM and tune them for your environment, specifically focusing on `process_creation` and `file_event` logs on Cisco Catalyst SD-WAN Manager appliances.
*   Enable comprehensive logging for `process_creation` and `file_event` on all Linux systems hosting Cisco Catalyst SD-WAN Manager to ensure the detection rules can effectively identify malicious activity.
*   Review and implement guidance from CISA's Binding Operational Directive (BOD) 22-01 regarding known exploited vulnerabilities and cloud services.
