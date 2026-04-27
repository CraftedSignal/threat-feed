---
title: Right-to-Left Override Character Used for Defense Evasion
slug: 2026-04-right-to-left-override
description: Adversaries are using the Right-to-Left Override (RTLO) character (U+202E) in command-line arguments to obfuscate malicious file names and trick users into executing them, achieving defense evasion.
date: "2026-04-01T11:57:31Z"
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

The Right-to-Left Override (RTLO) character (U+202E) is a Unicode character that causes text to be rendered from right to left. Adversaries are leveraging this character in Windows command-line arguments to obfuscate malicious file names and extensions. By embedding the RTLO character within a file name or command, attackers can visually reverse the order of characters, making a malicious file appear to be harmless. For example, a file named "evil.exe" might be renamed to "evil[U+202E]exe.pdf"…
