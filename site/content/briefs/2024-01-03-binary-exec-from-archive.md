---
brief_id: brief-2024-01-03-binary-exec-from-archive
event_id: brief-2024-01-03-binary-exec-from-archive
revision: 2
activity_at: "2026-11-20T01:37:27Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:37:27Z"
    checksum: sha256:b810e0528ec387f917c903f0a77118917b5bc022c03b3745756e91dfaeb55df7
    summary: exploited:true; KEV CVE-2025-0411
    changed_fields:
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - rules
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Windows Binary Execution from Archive-Related Paths
slug: 2024-01-03-binary-exec-from-archive
description: Detects the execution of a binary from archive-related paths within a user's Temp directory, potentially indicating attempts to bypass Mark-of-the-Web (MOTW) or exploit vulnerabilities like CVE-2025-0411.
date: "2024-01-03T15:00:00Z"
lastmod: "2026-11-20T01:36:50Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2025-02-06T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:windows:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ISHWARDEEPP-CVE-2025-0411-MOTW-POC&utm_source=rss&utm_medium=rss
tags:
  - binary-execution
  - archive-bypass
  - motw-bypass
  - privilege-escalation
  - windows
  - cve
vendors:
  - 7-Zip
  - Microsoft
  - Splunk
products:
  - Splunk Cloud
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Windows 10
  - Windows 11
product_versions:
  - product: Windows 10
    range: 10.0.17763.9020
  - product: Windows 10
    range: 10.0.19044.7548
  - product: Windows 10
    range: 10.0.19045.7548
  - product: Windows 11
    range: 10.0.26100.8875
affected_os:
  - Windows 10
  - Windows 11
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.002
    subtechnique_name: Malicious File
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    subtechnique_id: T1547.001
    subtechnique_name: Registry Run Keys / Startup Folder
    evidence: InstallService trusts plugin names and DLL paths from HKLM registry state, which can be modified by a low-privileged user.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: By creating specific registry keys, an attacker can force the InstallService to load an arbitrary attacker-controlled DLL.
    confidence_band: high
cves:
  - id: CVE-2025-0411
    cvss: 7
    epss: 0.67071
    kev: true
    kev_status: "true"
  - id: CVE-2026-50343
    kev_status: unknown
references:
  - https://redcanary.com/threat-detection-report/threats/scarlet-goldfinch/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_binary_execution_from_an_archive.yml
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ISHWARDEEPP-CVE-2025-0411-MOTW-POC&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RAT5AK-CVE-2026-50343-INSTALLSERVICE-EOP
rules:
  - title: Binary Executed from Archive-Related Temp Path
    description: Detects the execution of a binary from archive-related paths within the user's Temp directory.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Started by WinRAR
    description: Detects processes started by WinRAR that are located in the Temp directory, which is often abused by malware.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-08-29T13:45:03Z"
    level: L2
    summary: poc_available; OS windows 11; OS windows 10
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ISHWARDEEPP-CVE-2025-0411-MOTW-POC&utm_source=rss&utm_medium=rss
  - at: "2026-08-31T01:18:47Z"
    level: L2
    summary: 'added detection rule: Detect Suspicious InstallService State Registry Modification'
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RAT5AK-CVE-2026-50343-INSTALLSERVICE-EOP&utm_source=rss&utm_medium=rss
  - at: "2026-11-20T01:36:50Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-0411
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

This detection identifies suspicious execution patterns where Windows binaries are launched from archive-related paths within a user's temporary directory. This technique is often employed by attackers to circumvent security mechanisms like Mark-of-the-Web (MOTW), as seen in instances such as CVE-2025-0411. The detection focuses on binaries executed by trusted processes like `explorer.exe`, `winrar.exe`, and `7zFM.exe`. The targeted process paths include the user's Temp directory and archive markers like RAR, 7z, or ZIP. This behavior allows attackers to execute malicious code without triggering standard security alerts, making it crucial for defenders to monitor for this anomaly.

## Attack Chain

1.  A user receives a malicious archive file (e.g., RAR, ZIP, 7z) via phishing or drive-by download.
2.  The user opens the archive using `explorer.exe`, `winrar.exe`, or `7zFM.exe`.
3.  The archive contains a malicious executable file disguised as a legitimate document or media file.
4.  The executable is extracted to a temporary directory within the user's `AppData\Local\Temp\` folder.
5.  The user clicks on the extracted file, triggering its execution.
6.  Because the file was extracted from an archive and executed from the Temp directory, it might bypass Mark-of-the-Web (MOTW) protections.
7.  The malicious executable performs its intended actions, such as installing malware, establishing persistence, or exfiltrating data.
8.  The attacker gains unauthorized access to the system or network.

## Impact

Successful exploitation can lead to the installation of malware, data theft, and complete system compromise. By bypassing MOTW and other security measures, attackers can gain a foothold in the network and move laterally to access sensitive data. The impact can range from individual user compromises to large-scale data breaches, causing significant financial and reputational damage. The exploitation of CVE-2025-0411 and similar vulnerabilities can affect a wide range of users who regularly interact with archive files.

## Recommendation

*   Deploy the Sigma rule `Binary Executed from Archive-Related Temp Path` to your SIEM and tune for your environment to detect the execution of binaries from archive-related paths within the user's Temp directory.
*   Investigate any alerts generated by the Sigma rule, focusing on the parent process, executed path, and user context.
*   Implement application control policies to restrict the execution of binaries from temporary directories.
*   Educate users about the risks of opening suspicious archive files and clicking on extracted executables.
*   Monitor process execution events (Sysmon EventID 1 or CrowdStrike ProcessRollup2) for unusual parent-child process relationships involving archive extraction tools and executables.
