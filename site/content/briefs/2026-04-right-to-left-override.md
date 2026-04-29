---
title: Right-to-Left Override Character Used for Defense Evasion
slug: 2026-04-right-to-left-override
description: Adversaries are using the Right-to-Left Override (RTLO) character (U+202E) in command-line arguments to obfuscate malicious file names and trick users into executing them, achieving defense evasion.
date: "2026-04-01T11:57:31Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - defense-evasion
  - obfuscation
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://redcanary.com/blog/right-to-left-override/
  - https://www.malwarebytes.com/blog/news/2014/01/the-rtlo-method
  - https://unicode-explorer.com/c/202E
  - https://tria.ge/241015-l98snsyeje/behavioral2
  - https://unprotect.it/technique/right-to-left-override-rlo-extension-spoofing/
rules:
  - title: Detect Process Creation with Right-to-Left Override Character
    description: Detects process creation events where the command line contains the Right-to-Left Override (RTLO) character (U+202E).
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1036.002
    data_sources:
      - process_creation
      - windows
  - title: Detect File Creation with Right-to-Left Override Character
    description: Detects file creation events where the file name contains the Right-to-Left Override (RTLO) character (U+202E).
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1036.002
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Right-to-Left Override (RTLO) character (U+202E) is a Unicode character that causes text to be rendered from right to left. Adversaries are leveraging this character in Windows command-line arguments to obfuscate malicious file names and extensions. By embedding the RTLO character within a file name or command, attackers can visually reverse the order of characters, making a malicious file appear to be harmless. For example, a file named "evil.exe" might be renamed to "evil[U+202E]exe.pdf", which would display as "evilpdf.exe" to a user, potentially tricking them into executing the malicious file. This technique is used to bypass security controls and social engineering. The use of RTLO is not new, but it continues to be an effective method of tricking end users.

## Attack Chain

1.  An attacker crafts a malicious executable file (e.g., `trojan.exe`).
2.  The attacker renames the malicious file, embedding the RTLO character (U+202E) within the file name to reverse the visual presentation (e.g., `trojan[U+202E]exe.scr`).
3.  The renamed file (e.g., `trojanscr.exe`) is distributed to the target, often via phishing or other social engineering methods.
4.  The user, seeing the reversed file extension, mistakes the file for a screensaver file (`.scr`) and executes it.
5.  Upon execution, the malicious executable runs with the privileges of the user.
6.  The malware may then perform malicious activities such as installing additional malware, establishing persistence, or exfiltrating data.
7.  The attacker may use the initial foothold to escalate privileges and move laterally within the network.

## Impact

Successful exploitation can lead to the execution of arbitrary code, potentially compromising the entire system. This can result in data theft, system damage, or further propagation of malware within the network. The obfuscation technique makes it harder for users to identify malicious files, increasing the likelihood of successful attacks.

## Recommendation

*   Deploy the Sigma rule `Detect Process Creation with Right-to-Left Override Character` to your SIEM to detect processes spawned with the RTLO character in the command line.
*   Educate users about the risks of the RTLO character and how it can be used to disguise malicious files.
*   Implement file extension filtering to block execution of suspicious file types (e.g., `.exe`, `.scr`) from untrusted locations.
*   Monitor process creation events for unusual file names or command-line arguments containing the RTLO character.
*   Enable Sysmon process creation logging to capture command-line arguments, which is essential for detecting this technique.
