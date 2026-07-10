---
title: Adobe InDesign Out-of-Bounds Write Vulnerability (CVE-2026-27291)
slug: 2024-01-adobe-indesign-oob-write
description: Adobe InDesign Desktop versions 20.5.2, 21.2 and earlier are vulnerable to an out-of-bounds write (CVE-2026-27291), potentially allowing arbitrary code execution when a user opens a malicious file.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-27291
  - adobe-indesign
  - out-of-bounds-write
  - code-execution
vendors:
  - Adobe
products:
  - InDesign
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
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
cves:
  - id: CVE-2026-27291
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27291
  - https://helpx.adobe.com/security/products/indesign/apsb26-32.html
rules:
  - title: Detect Suspicious Child Process of InDesign
    description: Detects suspicious child processes spawned by Adobe InDesign, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect InDesign Spawning Unusual Network Connections
    description: Detects InDesign spawning network connections that are atypical and may indicate malicious activity after exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-27291 affects Adobe InDesign Desktop versions 20.5.2, 21.2, and earlier. This out-of-bounds write vulnerability can be exploited if a user opens a specially crafted, malicious file. Successful exploitation allows an attacker to execute arbitrary code within the security context of the current user. The attacker needs to convince the user to open the malicious file, indicating a social engineering aspect to the attack. This vulnerability poses a significant risk to organizations that rely on Adobe InDesign for creative work, as it could lead to system compromise and data breaches if exploited.

## Attack Chain

1. An attacker crafts a malicious Adobe InDesign file.
2. The attacker delivers the malicious file to a target user, possibly via email or other file-sharing methods.
3. The user, unaware of the file's malicious nature, opens it in a vulnerable version of Adobe InDesign (20.5.2, 21.2 or earlier).
4. InDesign attempts to process the file, triggering the out-of-bounds write vulnerability.
5. The out-of-bounds write leads to memory corruption.
6. The attacker leverages the memory corruption to inject and execute arbitrary code.
7. The attacker gains control of the InDesign process, inheriting the user's privileges.
8. The attacker can now perform malicious actions, such as installing malware, stealing data, or moving laterally within the network.

## Impact

Successful exploitation of CVE-2026-27291 can lead to arbitrary code execution on the targeted system, effectively allowing an attacker to take control of the application and potentially the entire machine. This could result in data theft, malware installation, or further network compromise. The vulnerability impacts all users of affected Adobe InDesign versions. While the number of affected users is not specified, the potential impact is widespread among creative professionals and organizations that rely on InDesign.

## Recommendation

*   Upgrade Adobe InDesign to a version beyond 21.2 to patch CVE-2026-27291 as indicated in Adobe's security advisory ([https://helpx.adobe.com/security/products/indesign/apsb26-32.html](https://helpx.adobe.com/security/products/indesign/apsb26-32.html)).
*   Deploy the provided Sigma rule to detect suspicious process creation events following the launch of InDesign to identify potential exploitation attempts.
*   Educate users about the risks of opening files from untrusted sources to mitigate the initial access vector.
