---
title: Adobe Photoshop Out-of-Bounds Read Vulnerability (CVE-2026-27289)
slug: 2026-04-photoshop-oob-read
description: An out-of-bounds read vulnerability (CVE-2026-27289) in Adobe Photoshop Desktop versions 27.4 and earlier allows for potential code execution via a crafted file, requiring user interaction to trigger the exploit.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-27289
  - out-of-bounds read
  - adobe photoshop
  - code execution
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27289
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27289
  - https://helpx.adobe.com/security/products/photoshop/apsb26-40.html
iocs:
  - type: email
    value: '[email&#160;protected]'
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 2
rules:
  - title: Detect Photoshop Opening Files From Suspicious Locations
    description: Detects Photoshop opening files from locations commonly associated with downloads or temporary storage, which could indicate a user opening a malicious file.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Child Processes of Photoshop
    description: Detects the creation of suspicious child processes spawned by Photoshop, which could be indicative of code execution following an exploit.
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

Adobe Photoshop Desktop versions 27.4 and earlier are vulnerable to an out-of-bounds read vulnerability (CVE-2026-27289). This flaw can be triggered when Photoshop parses a specially crafted file, leading to a read operation beyond the allocated memory boundary. Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code within the security context of the user running the application. The vulnerability requires user interaction, as a victim must open a malicious file in Photoshop to initiate the attack. This poses a risk to users who handle files from untrusted sources.

## Attack Chain

1.  Attacker crafts a malicious image file specifically designed to trigger the out-of-bounds read vulnerability in Adobe Photoshop.
2.  The attacker delivers the crafted file to the victim via email, shared drive, or other means.
3.  The victim, unaware of the malicious nature of the file, opens it using a vulnerable version of Adobe Photoshop (27.4 or earlier).
4.  Photoshop attempts to parse the crafted image file.
5.  Due to the malformed structure of the file, Photoshop's parsing routine attempts to read data beyond the allocated buffer.
6.  The out-of-bounds read occurs, potentially exposing sensitive information or causing a crash.
7.  An attacker leverages the out-of-bounds read to gain control of program execution flow.
8.  The attacker executes arbitrary code within the context of the user running Photoshop, potentially leading to system compromise.

## Impact

Successful exploitation of CVE-2026-27289 can lead to arbitrary code execution on the victim's machine.  Since the code runs within the user's context, the attacker gains the same privileges as the user.  This could enable the attacker to install malware, steal sensitive data, or pivot to other systems on the network. While the specific number of affected users isn't specified, all users running versions 27.4 and earlier are potentially vulnerable, with the most likely targets being graphic designers, photographers, and other creative professionals.

## Recommendation

*   Upgrade Adobe Photoshop to a version greater than 27.4 to patch CVE-2026-27289.
*   Implement user awareness training to educate users about the risks of opening files from untrusted sources to mitigate the initial access vector.
*   Monitor process creation events for suspicious Photoshop processes using the provided Sigma rule to detect potential exploitation attempts.
*   Enable file access monitoring to identify instances where Photoshop opens unusual or suspicious files, which could be indicative of malicious activity.
