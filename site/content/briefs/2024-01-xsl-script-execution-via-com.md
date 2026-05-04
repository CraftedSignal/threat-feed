---
title: XSL Script Execution via COM Interface in Microsoft Office
slug: 2024-01-xsl-script-execution-via-com
description: Adversaries may exploit Microsoft Office applications to execute malicious JScript or VBScript by leveraging the Microsoft.XMLDOM COM interface to process and transform XML documents using XSL scripts, potentially leading to initial access or defense evasion.
date: "2024-01-26T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xsl-script
  - com-interface
  - office-macro
vendors:
  - Microsoft
products:
  - Microsoft Office
  - Excel
  - PowerPoint
  - Word
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1220
    technique_name: XSL Script Processing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Inter-Process Communication
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_xsl_script_execution_via_com.toml
  - https://attack.mitre.org/techniques/T1220/
rules:
  - title: XSL Script Execution via COM
    description: Detects the execution of a hosted XSL script using the Microsoft.XMLDOM COM interface via Microsoft Office processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - initial_access
    techniques:
      - T1220
      - T1559.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Office Application Loading MSXML3.dll
    description: Detects Office applications loading the msxml3.dll library, which can be indicative of XSL script processing.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1220
    data_sources:
      - image_load
      - windows
rules_count: 2
---

Attackers are increasingly leveraging the Microsoft.XMLDOM COM interface in Microsoft Office applications to execute malicious scripts. This technique involves embedding malicious JScript or VBScript within XSL transformations, which are then processed by Office applications like Word, Excel, PowerPoint, and Publisher. The exploitation begins when a user opens a specially crafted document. This campaign abuses legitimate functionalities for malicious purposes. This technique can be used for initial access, defense evasion, and execution of arbitrary code. The observed behavior includes the loading of `msxml3.dll` and the spawning of child processes.

## Attack Chain

1. A user receives a phishing email containing a malicious Office document.
2. The user opens the document in Microsoft Word (winword.exe), Excel (excel.exe), PowerPoint (powerpnt.exe), or Publisher (mspub.exe).
3. The Office application loads `msxml3.dll` to process XML content within the document.
4. The document contains an embedded XSL script with malicious JScript or VBScript code.
5. The XSL transformation is initiated, executing the embedded script via the COM interface.
6. The script spawns a new process (cmd.exe, powershell.exe, or mshta.exe) to execute arbitrary commands.
7. The spawned process downloads and executes a payload from a remote server.
8. The payload establishes persistence, escalates privileges, and performs malicious activities such as data exfiltration or lateral movement.

## Impact

Successful exploitation can lead to arbitrary code execution, potentially compromising sensitive data and allowing attackers to gain initial access to the targeted system. This can result in data breaches, financial losses, and reputational damage. The scope of impact includes any Windows systems running vulnerable versions of Microsoft Office. If successful, the attacker can achieve persistence, perform lateral movement and compromise other systems on the network.

## Recommendation

*   Deploy the Sigma rule "XSL Script Execution via COM" to your SIEM to detect the execution of hosted XSL scripts using the Microsoft.XMLDOM COM interface.
*   Monitor for the loading of `msxml3.dll` by Microsoft Office applications and subsequent process creations to identify potential exploitation attempts.
*   Implement application whitelisting to restrict the execution of unauthorized scripts and executables, particularly those not located in standard directories.
*   Block the execution of unusual or unsigned child processes spawned by Microsoft Office applications to prevent malicious script execution.
*   Educate users about the risks of opening suspicious attachments or clicking on links in phishing emails (T1566).
