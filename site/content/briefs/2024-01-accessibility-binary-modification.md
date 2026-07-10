---
title: Potential Modification of Accessibility Binaries for Persistence and Privilege Escalation
slug: 2024-01-accessibility-binary-modification
description: Adversaries can modify accessibility binaries to execute malicious code before user login, establishing persistence and potentially escalating privileges by replacing legitimate accessibility tools with backdoored executables.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://www.elastic.co/blog/practical-security-engineering-stateful-detection
  - https://attack.mitre.org/techniques/T1546/008/
rules:
  - title: Potential Modification of Accessibility Binaries
    description: Detects the execution of accessibility binaries with an original file name that doesn't match the expected name, indicating potential modification.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.008
    data_sources:
      - process_creation
      - windows
  - title: Accessibility Features Launched from Winlogon
    description: Detects when common accessibility features are launched directly from winlogon.exe, which could indicate malicious use.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.008
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Windows accessibility features, designed to aid users with disabilities, can be abused by attackers to gain unauthorized access. These features, such as Narrator, Magnifier, and On-Screen Keyboard, can be launched from the login screen before a user logs in. By replacing the legitimate executables associated with these features with malicious binaries, an attacker can achieve code execution with elevated privileges as SYSTEM. This technique allows for persistence, as the malicious code will be executed every time the accessibility feature is launched. The detection rule focuses on identifying process executions where the launched accessibility binary does not match its expected original file name, a strong indicator of malicious modification. The scope of this threat extends to any Windows system where accessibility features are enabled, potentially impacting a wide range of users and organizations.

## Attack Chain

1. An attacker gains initial access to the target system (e.g., through remote code execution or physical access).
2. The attacker identifies accessible features binaries such as `Utilman.exe`, `osk.exe`, `Magnify.exe`, `Narrator.exe`, and `sethc.exe`.
3. The attacker replaces one or more of these legitimate binaries with a malicious executable. This could involve renaming the original binary and placing the malicious executable in its place, using the original name.
4. The system is restarted or the user logs out, returning to the login screen.
5. An unsuspecting user attempts to launch the replaced accessibility feature (e.g., by pressing the Shift key five times to launch Sticky Keys, which is typically associated with `sethc.exe`).
6. Instead of the intended accessibility feature, the malicious executable is launched with SYSTEM privileges, granting the attacker code execution in a privileged context.
7. The malicious executable might then establish persistence (e.g., by creating a new service or modifying registry keys) or perform other malicious activities, such as installing a backdoor or exfiltrating data.
8. The attacker can now remotely access the compromised system, bypassing normal authentication procedures due to the elevated privileges gained.

## Impact

Successful exploitation allows attackers to gain persistent access to systems with SYSTEM privileges, bypassing normal authentication. This can lead to complete system compromise, data theft, installation of backdoors, and lateral movement within the network. While the number of victims is unknown, the potential impact is widespread across all sectors due to the commonality of Windows operating systems and the built-in accessibility features. A successful attack grants an attacker complete control over the compromised system.

## Recommendation

*   Deploy the Sigma rule "Potential Modification of Accessibility Binaries" to your SIEM and tune for your environment to detect the execution of modified accessibility binaries.
*   Regularly audit and monitor changes to accessibility binaries in `C:\Windows\System32\` using file integrity monitoring (FIM) tools and the file_event log source.
*   Implement strict access control policies to limit who can modify files in the `C:\Windows\System32\` directory.
*   Educate users about the risks of running unknown executables, especially those that masquerade as system utilities.
