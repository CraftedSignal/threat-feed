---
title: Adobe Premiere Pro Out-of-Bounds Write Vulnerability (CVE-2026-34636)
slug: 2026-05-adobe-premiere-oob-write
description: Adobe Premiere Pro versions 26.0.2, 25.6.4 and earlier are affected by an out-of-bounds write vulnerability (CVE-2026-34636) that could lead to arbitrary code execution when a user opens a malicious file.
date: "2026-05-12T18:25:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - adobe
  - premiere pro
  - out-of-bounds write
  - code execution
vendors:
  - Adobe Systems Incorporated
products:
  - Premiere Pro (<= 26.0.2)
  - Premiere Pro (<= 25.6.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-34636
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34636
  - https://helpx.adobe.com/security/products/premiere_pro/apsb26-46.html
rules:
  - title: Detect Suspicious Premiere Pro File Opening
    description: Detects CVE-2026-34636 exploitation attempt by monitoring for Premiere Pro opening suspicious files.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Child Processes of Premiere Pro
    description: Detects suspicious child processes spawned by Premiere Pro, potentially indicating code execution (CVE-2026-34636).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Adobe Premiere Pro versions 26.0.2, 25.6.4 and earlier are vulnerable to an out-of-bounds write vulnerability (CVE-2026-34636). This vulnerability exists because of a flaw in how Premiere Pro processes certain file formats. A successful exploit could allow an attacker to execute arbitrary code with the privileges of the current user. User interaction is required to trigger the vulnerability, as the victim must open a specially crafted malicious file. This can be achieved by enticing a user to download and open a file sent via email, or hosted on a website.

## Attack Chain

1.  Attacker crafts a malicious project file specifically designed to trigger the out-of-bounds write vulnerability in Adobe Premiere Pro.
2.  The attacker delivers the malicious file to a target user, possibly via phishing email, social engineering, or a compromised website.
3.  The user, unaware of the malicious nature of the file, opens it within Adobe Premiere Pro (versions 26.0.2, 25.6.4 or earlier).
4.  Premiere Pro attempts to parse the malicious data within the file, triggering the out-of-bounds write.
5.  The out-of-bounds write allows the attacker to overwrite memory locations with attacker-controlled data.
6.  The attacker overwrites critical code pointers or data structures in memory.
7.  The attacker hijacks control flow and redirects execution to attacker-supplied code.
8.  The attacker achieves arbitrary code execution within the context of the current user, potentially installing malware, stealing sensitive data, or performing other malicious actions.

## Impact

Successful exploitation of CVE-2026-34636 allows an attacker to execute arbitrary code on a vulnerable system, potentially leading to complete system compromise. The attacker gains the same privileges as the user running Premiere Pro, which may include access to sensitive files, network resources, and other applications. This can lead to data theft, malware installation, or further lateral movement within the network.

## Recommendation

*   Upgrade to a supported version of Adobe Premiere Pro that has patched CVE-2026-34636 to prevent exploitation of this vulnerability.
*   Implement user awareness training to educate users about the risks of opening files from untrusted sources to mitigate the initial access vector.
*   Deploy the Sigma rule "Detect Suspicious Premiere Pro File Opening" to identify potential attempts to exploit the vulnerability by monitoring file opening events.
*   Enable process monitoring to detect suspicious child processes spawned by Premiere Pro after opening project files.
