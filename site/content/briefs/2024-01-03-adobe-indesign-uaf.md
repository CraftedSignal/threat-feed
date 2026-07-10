---
title: Adobe InDesign Use-After-Free Vulnerability (CVE-2026-27283)
slug: 2024-01-03-adobe-indesign-uaf
description: Adobe InDesign Desktop versions 20.5.2, 21.2 and earlier are susceptible to a use-after-free vulnerability (CVE-2026-27283), potentially leading to arbitrary code execution if a user opens a specially crafted file.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-27283
  - adobe
  - indesign
  - use-after-free
  - execution
vendors:
  - Adobe
products:
  - InDesign
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-27283
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27283
  - https://helpx.adobe.com/security/products/indesign/apsb26-32.html
rules:
  - title: Detect InDesign Suspicious File Opens
    description: Detects suspicious process creation events where InDesign opens a file, potentially indicating exploitation of CVE-2026-27283.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect InDesign Writing Suspicious Files
    description: Detects InDesign writing files to suspicious locations. This may indicate possible payload dropping
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1027
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-27283 is a use-after-free vulnerability affecting Adobe InDesign Desktop versions 20.5.2, 21.2, and earlier. This vulnerability can be exploited when a user opens a malicious InDesign file. Successful exploitation could lead to arbitrary code execution within the context of the current user. The vulnerability was reported to Adobe and assigned a CVSS v3.1 base score of 7.8, indicating a high severity. This vulnerability requires user interaction. The report highlights that a victim must open a malicious file for the exploitation to occur. Organizations utilizing vulnerable versions of InDesign should take appropriate actions to mitigate this risk.

## Attack Chain

1.  Attacker crafts a malicious Adobe InDesign file designed to trigger the use-after-free vulnerability.
2.  The attacker delivers the malicious InDesign file to the victim via email or other file-sharing methods.
3.  The victim, unaware of the malicious nature, opens the crafted InDesign file using a vulnerable version of Adobe InDesign Desktop (20.5.2, 21.2, or earlier).
4.  InDesign attempts to access a memory location that has already been freed, triggering the use-after-free condition.
5.  The attacker gains control of the program counter due to the memory corruption.
6.  The attacker injects and executes arbitrary code within the context of the InDesign process.
7.  The attacker escalates privileges or performs malicious actions such as installing malware, stealing data, or compromising the system.

## Impact

Successful exploitation of CVE-2026-27283 allows for arbitrary code execution within the context of the user running Adobe InDesign. This could allow an attacker to install programs, view, change, or delete data, or create new accounts with full user rights. The vulnerability affects Adobe InDesign Desktop users, potentially impacting creative professionals and organizations that rely on InDesign for their workflows. The vulnerability requires user interaction to trigger.

## Recommendation

*   Deploy the Sigma rule "Detect InDesign Suspicious File Opens" to identify potential attempts to exploit CVE-2026-27283 by monitoring process creation events related to InDesign opening files (see rules).
*   Educate users about the risks of opening files from untrusted sources and the importance of verifying the legitimacy of InDesign files before opening them.
*   Monitor file creation events for InDesign processes creating suspicious files (see rules).
*   Refer to Adobe's security bulletin APSB26-32 for official guidance and updates regarding CVE-2026-27283 (references).
