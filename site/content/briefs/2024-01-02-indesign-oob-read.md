---
title: Adobe InDesign Out-of-Bounds Read Vulnerability (CVE-2026-27284)
slug: 2024-01-02-indesign-oob-read
description: Adobe InDesign Desktop versions 20.5.2, 21.2 and earlier are vulnerable to an out-of-bounds read (CVE-2026-27284) when parsing a crafted file, potentially leading to code execution if a user opens a malicious file.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-27284
  - adobe-indesign
  - out-of-bounds-read
  - code-execution
vendors:
  - Adobe
products:
  - InDesign Desktop
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-27284
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27284
  - https://helpx.adobe.com/security/products/indesign/apsb26-32.html
rules:
  - title: Detect InDesign Spawning Suspicious Child Process
    description: Detects InDesign spawning a suspicious child process, which could indicate exploitation of CVE-2026-27284 leading to code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect InDesign Writing Executables to Disk
    description: Detects InDesign writing executable files to disk, which could be a sign of malware being dropped after exploiting CVE-2026-27284.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1027
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-27284 is an out-of-bounds read vulnerability affecting Adobe InDesign Desktop versions 20.5.2, 21.2, and earlier. The vulnerability occurs when the application parses a maliciously crafted file, potentially leading to a read operation beyond the allocated memory boundary. This could allow an attacker to execute arbitrary code with the privileges of the logged-on user. Successful exploitation of this vulnerability requires user interaction; a victim must open a specifically crafted InDesign file provided by the attacker. This vulnerability poses a risk to organizations where InDesign is used for processing potentially untrusted documents, such as in creative agencies or publishing houses. The report was published on 2026-04-14.

## Attack Chain

1.  Attacker crafts a malicious InDesign file designed to trigger the out-of-bounds read vulnerability.
2.  The attacker delivers the malicious file to a target user, potentially through email, shared storage, or a compromised website.
3.  The user opens the malicious InDesign file using a vulnerable version of Adobe InDesign (20.5.2, 21.2 or earlier).
4.  InDesign attempts to parse the crafted file, which contains malformed data structures designed to trigger the vulnerability.
5.  During parsing, InDesign attempts to read data beyond the allocated buffer, triggering the out-of-bounds read.
6.  The out-of-bounds read leads to an exploitable condition, such as overwriting a return address or other critical data in memory.
7.  The attacker gains control of the program counter and executes arbitrary code in the context of the current user.
8.  The attacker can then perform malicious actions such as installing malware, stealing sensitive data, or gaining persistent access to the system.

## Impact

Successful exploitation of CVE-2026-27284 allows an attacker to execute arbitrary code in the context of the logged-on user. This can lead to the complete compromise of the affected system, including data theft, malware installation, and potentially lateral movement within the network. The impact is significant, especially in environments where InDesign is used to handle sensitive information or as part of critical workflows. If successful, attackers could potentially compromise intellectual property, customer data, or other confidential information.

## Recommendation

*   Apply the security update provided by Adobe to address CVE-2026-27284 (reference: https://helpx.adobe.com/security/products/indesign/apsb26-32.html).
*   Deploy the Sigma rule to detect suspicious InDesign process behavior indicative of exploitation (see rules below).
*   Educate users about the risks of opening untrusted or unexpected files, especially from external sources.
*   Monitor process creation events for InDesign spawning child processes or accessing unusual network resources.
