---
brief_id: brief-2024-01-03-anonymous-computer-change
event_id: brief-2024-01-03-anonymous-computer-change
revision: 2
activity_at: "2026-11-20T03:11:01Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:11:01Z"
    checksum: sha256:3d9cdad746de33faedc7db91bfca447ecc53486d528d78ac7479025271011651
    summary: exploited:true; KEV CVE-2020-1472
    changed_fields:
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - rules
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Computer Account Changes via Anonymous Logon Detected
slug: 2024-01-anonymous-computer-change
description: Detection of Windows Event 4742 indicating a computer account change performed by an ANONYMOUS LOGON account, which is abnormal and could signify malicious activity, particularly Zerologon exploitation.
date: "2024-01-03T18:15:00Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2021-11-03T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:synology:directory_server:*:*:*:*:*:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:14.04:*:*:*:esm:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:16.04:*:*:*:esm:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:16.04:*:*:*:lts:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:18.04:*:*:*:lts:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:31:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:32:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_1903:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_1909:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2004:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_20h2:-:*:*:*:*:*:*:*
  - cpe:2.3:o:opensuse:leap:15.1:*:*:*:*:*:*:*
  - cpe:2.3:o:opensuse:leap:15.2:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CANCIUCOSTIN-CVE-2020-1472&utm_source=rss&utm_medium=rss
tags:
  - zerologon
  - privilege-escalation
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Cloud
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Windows Server 1903
  - Windows Server 1909
  - Windows Server 2004
  - Windows Server 2008
affected_os:
  - Windows Server 1903
  - Windows Server 1909
  - Windows Server 2004
  - Windows Server 2008
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2020-1472
    cvss: 5.5
    epss: 0.99512
    kev: true
    kev_status: "true"
references:
  - https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/
  - https://netwrix.com/en/cybersecurity-glossary/cyber-security-attacks/zerologon-vulnerability/
  - https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx
  - https://github.com/splunk/security_content/blob/main/detections/network/detect_zerologon_via_zeek.yml
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CANCIUCOSTIN-CVE-2020-1472&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Computer Changed with Anonymous Logon
    description: Detects changes to computer accounts using an anonymous logon, indicative of potential Zerologon exploitation.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - windows
      - windows
rules_count: 1
updates:
  - at: "2026-05-28T17:47:49Z"
    level: L1
    summary: new IOCs
    sources:
      - splunk-escu
  - at: "2026-08-31T17:06:11Z"
    level: L2
    summary: poc_available; added CVE-2020-1472; OS windows server 1903; OS windows server 1909; OS windows server 2004; OS windows server 2008
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CANCIUCOSTIN-CVE-2020-1472&utm_source=rss&utm_medium=rss
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2020-1472
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

This threat brief addresses the detection of anomalous computer account modifications within a Windows environment. The activity is flagged by monitoring Windows Security Event Log ID 4742 ("A computer account was changed") where the SubjectUserName is "ANONYMOUS LOGON". This event sequence is highly unusual because computer account changes should not originate from anonymous logons. It's often associated with exploitation attempts against CVE-2020-1472 (Zerologon), which allows attackers to reset the computer account password to an empty value. Successful exploitation can grant attackers domain administrator privileges. This poses a critical threat to organizations as it can lead to complete domain compromise. The detection focuses on the specific event sequence as a reliable indicator of potential Zerologon exploitation or related unauthorized activities.

## Attack Chain

1.  Attacker gains initial access to the network (often internal).
2.  Attacker sends a series of Netlogon messages to the domain controller using the "ANONYMOUS LOGON" account.
3.  These messages exploit a cryptographic flaw (CVE-2020-1472) in the Netlogon protocol.
4.  The attacker successfully resets the domain controller's computer account password to an empty string.
5.  Windows Security Event 4742 is generated with SubjectUserName of "ANONYMOUS LOGON", indicating the computer account change.
6.  The attacker uses the now-empty password to authenticate to the domain controller as the computer account.
7.  Attacker obtains domain administrator privileges by leveraging the compromised computer account.
8.  Attacker performs malicious activities such as data exfiltration, ransomware deployment, or establishing persistent access.

## Impact

Successful exploitation of this vulnerability and subsequent account takeover results in complete compromise of the Active Directory domain. This allows the attacker to steal sensitive data, deploy ransomware across the network, and gain persistent access to critical systems. This could result in millions of dollars in damages, regulatory fines, and reputational damage. The Zerologon vulnerability (CVE-2020-1472) has been widely exploited, and unpatched systems remain at high risk.

## Recommendation

*   Deploy the Sigma rule "Detect Computer Changed with Anonymous Logon" to your SIEM and tune for your environment to detect Event ID 4742 with "ANONYMOUS LOGON" as SubjectUserName (see "rules" section).
*   Ensure that the "Audit Computer Account Management" sub-category within the Windows Audit Policy is enabled to generate Event ID 4742 (see "how_to_implement" section).
*   Prioritize patching systems vulnerable to CVE-2020-1472 to prevent exploitation via the Netlogon protocol. (see "cve" tag)
*   Review systems for evidence of CVE-2020-1472 exploitation attempts using references provided such as https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/.
