---
title: Adobe Acrobat Reader Prototype Pollution Vulnerability (CVE-2026-34621)
slug: 2026-04-acrobat-prototype-pollution
description: A prototype pollution vulnerability, identified as CVE-2026-34621, exists in Adobe Acrobat Reader versions 24.001.30356, 26.001.21367 and earlier, potentially leading to arbitrary code execution when a user opens a malicious file.
date: "2026-04-11T07:17:00Z"
severities:
  - critical
tags:
  - cve-2026-34621
  - acrobat reader
  - prototype pollution
  - arbitrary code execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-34621
    cvss: 9.6
    epss: 0.07596
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34621
  - https://helpx.adobe.com/security/products/acrobat/apsb26-43.html
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Acrobat Reader Suspicious Child Process
    description: Detects suspicious child processes spawned by Adobe Acrobat Reader, potentially indicating exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Acrobat Reader Network Connection to Non-Standard Ports
    description: Detects suspicious network connections initiated by Adobe Acrobat Reader to non-standard ports.
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

CVE-2026-34621 describes a critical vulnerability affecting Adobe Acrobat Reader versions 24.001.30356, 26.001.21367, and earlier. This vulnerability is classified as an Improperly Controlled Modification of Object Prototype Attributes, also known as 'Prototype Pollution'. The vulnerability's exploitation could lead to arbitrary code execution within the context of the current user. The attack requires user interaction, specifically the opening of a specially crafted malicious file by the victim. Successful exploitation could allow an attacker to gain control over the user's system. This vulnerability was published on April 11, 2026, and poses a significant threat to users of the affected Acrobat Reader versions, warranting immediate patching or mitigation measures.

## Attack Chain

1.  **Attacker Crafting Malicious PDF:** An attacker creates a malicious PDF file specifically designed to exploit the prototype pollution vulnerability (CVE-2026-34621) in Adobe Acrobat Reader.
2.  **Delivery of Malicious PDF:** The attacker delivers the crafted PDF to the victim through various means, such as email attachment or a link on a malicious website.
3.  **User Opens the Malicious PDF:** The victim unknowingly opens the malicious PDF file using a vulnerable version of Adobe Acrobat Reader (24.001.30356, 26.001.21367 or earlier).
4.  **Exploitation of Prototype Pollution:** The malicious PDF leverages JavaScript or other embedded scripting to manipulate object prototype attributes within the Acrobat Reader environment. This manipulation is designed to inject malicious properties into the base object prototype.
5.  **Code Execution:** When Acrobat Reader attempts to access or use an object with the polluted prototype, the injected malicious properties are executed.
6.  **Privilege Escalation (Context of Current User):** The malicious code executes within the context of the current user, granting the attacker the same privileges as the user running Acrobat Reader.
7.  **Persistence and Lateral Movement:** The attacker may attempt to establish persistence by modifying system files or registry keys, allowing continued access to the compromised system. The attacker may also attempt to move laterally within the network, compromising other systems and accessing sensitive data.
8.  **Arbitrary Code Execution:** The attacker achieves arbitrary code execution, allowing them to install malware, steal sensitive information, or perform other malicious actions.

## Impact

Successful exploitation of CVE-2026-34621 allows an attacker to execute arbitrary code on the victim's machine with the user's privileges. This can result in data theft, malware installation, and potentially complete system compromise. Given the widespread use of Adobe Acrobat Reader across various sectors, a successful attack could affect a large number of users and organizations. The impact ranges from individual data breaches to significant organizational security incidents.

## Recommendation

*   Immediately update Adobe Acrobat Reader to a version beyond 24.001.30356 and 26.001.21367 to patch CVE-2026-34621.
*   Deploy the Sigma rule "Detect Acrobat Reader Suspicious Child Process" to identify potential exploitation attempts via spawned processes.
*   Implement user awareness training to educate users about the risks of opening unsolicited or suspicious PDF attachments to prevent initial access.
*   Monitor process creation events for unexpected child processes spawned by `AcroRd32.exe` using process creation logs.
