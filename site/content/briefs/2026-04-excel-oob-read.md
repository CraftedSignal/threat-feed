---
title: Microsoft Excel Out-of-Bounds Read Vulnerability (CVE-2026-32188)
slug: 2026-04-excel-oob-read
description: An out-of-bounds read vulnerability in Microsoft Office Excel (CVE-2026-32188) allows a local attacker to potentially disclose sensitive information through a maliciously crafted Excel file.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - excel
  - out-of-bounds read
  - cve-2026-32188
  - information disclosure
  - vulnerability
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-32188
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32188
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32188
rules:
  - title: Detect Suspicious Excel Process Creation
    description: Detects Excel spawning child processes, which can be indicative of exploitation or macro execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Excel Opening Network Connections
    description: Detects Excel making network connections, which may be a sign of malicious macro execution or exploitation.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32188 describes an out-of-bounds read vulnerability affecting Microsoft Office Excel. According to the NVD, this vulnerability allows an unauthorized attacker to disclose information locally. The CVSS v3.1 score is 7.1, indicating a high severity. The vulnerability resides within how Excel parses certain file formats, potentially allowing a malicious actor to craft a file that, when opened, causes Excel to read memory outside of allocated buffers. This can lead to the disclosure of sensitive information contained in the application's memory space. While the source doesn't specify affected versions or a specific attack campaign, successful exploitation requires user interaction to open the malicious file. Defenders should focus on detecting abnormal process behavior in Excel and promptly applying available patches.

## Attack Chain

1. An attacker crafts a malicious Excel file designed to trigger the out-of-bounds read vulnerability (CVE-2026-32188).
2. The attacker delivers the crafted Excel file to a victim via social engineering or other means.
3. The victim opens the malicious Excel file.
4. Excel attempts to parse the malformed data structures within the file.
5. Due to the vulnerability, Excel reads memory outside the intended buffer boundaries.
6. The out-of-bounds read results in the disclosure of sensitive information from Excel's memory.
7. The attacker retrieves the disclosed information, potentially containing sensitive data or internal application state.
8. The attacker uses the disclosed information for further malicious activities.

## Impact

Successful exploitation of CVE-2026-32188 can lead to the disclosure of sensitive information from the victim's system. While the vulnerability is local, the disclosed information could include credentials, internal network details, or other sensitive data that could be used for further attacks. The number of potential victims is broad, encompassing any user of Microsoft Office Excel. The impact could range from minor data leaks to more significant compromises depending on the nature of the disclosed information.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-32188 on all affected systems. Reference the Microsoft advisory linked in the references section for specific instructions.
*   Implement the Sigma rule "Detect Suspicious Excel Process Creation" to identify potentially malicious Excel activity.
*   Monitor for unusual network connections originating from Excel processes after opening untrusted documents.
*   Educate users about the risks of opening unsolicited or suspicious Excel files to prevent initial access.
