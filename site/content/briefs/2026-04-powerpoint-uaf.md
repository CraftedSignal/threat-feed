---
title: Microsoft PowerPoint Use-After-Free Vulnerability (CVE-2026-32200)
slug: 2026-04-powerpoint-uaf
description: CVE-2026-32200 is a use-after-free vulnerability in Microsoft Office PowerPoint that allows an unauthorized attacker to achieve local code execution by enticing a user to open a specially crafted PowerPoint document.
date: "2026-04-14T18:17:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-32200
  - use-after-free
  - powerpoint
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-32200
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32200
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32200
iocs:
  - type: email
    value: '[email protected]'
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 2
rules:
  - title: Detect Suspicious PowerPoint Child Processes
    description: Detects suspicious child processes spawned by PowerPoint, indicating potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerPoint launching MSHTA
    description: Detects potential exploitation via PowerPoint launching MSHTA.exe, which is often used to execute HTA files.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32200 is a use-after-free vulnerability affecting Microsoft Office PowerPoint. An unauthenticated, local attacker can exploit this flaw to achieve arbitrary code execution. The attacker needs to convince a user to open a malicious PowerPoint file. Successful exploitation allows the attacker to execute code with the privileges of the current user. Given the widespread use of PowerPoint in corporate environments and the potential for phishing attacks delivering malicious documents, this vulnerability poses a significant risk. The vulnerability was reported to Microsoft and assigned a CVSS v3.1 score of 7.8.

## Attack Chain

1.  The attacker crafts a malicious PowerPoint document (.ppt or .pptx) specifically designed to trigger the use-after-free vulnerability.
2.  The attacker distributes the malicious PowerPoint file to a target victim via email, shared network drive, or other means.
3.  The victim opens the malicious PowerPoint file using a vulnerable version of Microsoft Office PowerPoint.
4.  PowerPoint attempts to access a memory location that has already been freed due to a flaw in its handling of specific document elements.
5.  The use-after-free condition leads to memory corruption, allowing the attacker to overwrite critical data structures.
6.  The attacker leverages the memory corruption to redirect the program's execution flow to attacker-controlled code.
7.  The attacker's code executes within the context of the PowerPoint process.
8.  The attacker gains arbitrary code execution on the victim's machine, potentially installing malware, stealing sensitive data, or performing other malicious actions.

## Impact

Successful exploitation of CVE-2026-32200 allows a local attacker to execute arbitrary code on a vulnerable system. This could lead to complete system compromise, including the installation of malware, data theft, and privilege escalation. Given the prevalence of PowerPoint in enterprise environments, a successful attack could impact a large number of users and organizations. The CVSS v3.1 score of 7.8 indicates a high severity vulnerability due to the potential for significant impact on confidentiality, integrity, and availability.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious PowerPoint Child Processes` to identify potential exploitation attempts based on spawned processes (see rules).
*   Monitor process creation events for `powerpnt.exe` spawning suspicious child processes using process creation logs.
*   Block or quarantine any PowerPoint documents originating from untrusted sources.
*   Apply the patch released by Microsoft to address CVE-2026-32200 as soon as possible after it becomes available (reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32200).
