---
title: Potential Fake CAPTCHA Phishing Attack via Malicious Copy/Paste
slug: 2024-01-fake-captcha-phishing
description: Attackers compromise websites, inject malicious code posing as fake CAPTCHAs, and trick users into copying and pasting malicious commands into the Windows Run dialog box, leading to the execution of PowerShell, Cmd, or MSHTA.
date: "2024-01-01T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - social-engineering
  - malware
  - windows
vendors:
  - Microsoft
products:
  - Windows
  - PowerShell
  - cmd.exe
  - mshta.exe
mitre_ttps:
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
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/004/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/techniques/T1189/
  - https://attack.mitre.org/techniques/T1566/
  - https://attack.mitre.org/techniques/T1566/001/
rules:
  - title: Detect Fake CAPTCHA PowerShell Command
    description: Detects PowerShell commands with suspicious CAPTCHA-related keywords in the command line, indicative of a potential phishing attack.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Fake CAPTCHA CMD Command
    description: Detects CMD commands with suspicious CAPTCHA-related keywords in the command line, indicative of a potential phishing attack.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat involves attackers compromising websites and injecting malicious code to deliver fake CAPTCHA or page error messages to unsuspecting users. The goal is to trick victims into copying malicious commands from the compromised website and pasting them into the Windows Run dialog box. This technique leverages social engineering and user interaction to bypass traditional security measures. The malicious commands often involve PowerShell, cmd.exe, or mshta.exe, enabling the execution of arbitrary code on the victim's machine. The use of common system binaries makes detection challenging, as these are typically trusted processes. This activity has been observed since 2025/08/19.

## Attack Chain

1. **Website Compromise:** Attackers compromise a legitimate website using various techniques, such as exploiting vulnerabilities or using stolen credentials.
2. **Malicious Code Injection:** The compromised website is injected with malicious JavaScript code that displays a fake CAPTCHA or error message to visitors.
3. **Social Engineering:** The fake CAPTCHA or error message instructs the user to copy a provided command to resolve the issue. The message often creates a sense of urgency or importance to compel the user to act.
4. **Command Execution:** The user copies the malicious command, which typically includes PowerShell, cmd.exe, or mshta.exe with obfuscated or encoded arguments.
5. **Payload Download:** The executed command downloads and executes a secondary payload from a remote server.
6. **Persistence:** The payload establishes persistence mechanisms, such as creating scheduled tasks or modifying registry keys, to ensure continued access to the compromised system.
7. **Lateral Movement:** Depending on the attacker's objectives, they may attempt to move laterally within the network to compromise additional systems.
8. **Objective Completion:** The ultimate objective may involve data theft, ransomware deployment, or other malicious activities.

## Impact

Successful execution of this attack can result in the compromise of user systems, leading to potential data theft, malware installation, and further network intrusion. The widespread use of this technique highlights the need for increased user awareness and robust security measures to detect and prevent malicious copy-paste activity. While specific numbers are not available, similar phishing campaigns have affected numerous users across various sectors.

## Recommendation

*   Deploy the Sigma rule `Detect Fake CAPTCHA PowerShell Command` to your SIEM to detect the execution of PowerShell commands containing CAPTCHA-related keywords.
*   Deploy the Sigma rule `Detect Fake CAPTCHA CMD Command` to your SIEM to detect the execution of CMD commands containing CAPTCHA-related keywords.
*   Implement user awareness training to educate users about the risks of copying and pasting commands from untrusted sources (reference: Attack Chain step 3).
*   Monitor process execution logs for suspicious command-line arguments involving PowerShell, cmd.exe, and mshta.exe (reference: Attack Chain step 4).
