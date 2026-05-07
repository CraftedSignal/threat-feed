---
title: Microsoft Office for Mac Sandbox Escape via Faulty Regex
slug: 2024-01-office-sandbox-escape
description: A vulnerability in Microsoft Office for Mac allows malicious code to escape the application's sandbox and achieve persistence by abusing a faulty regex for temporary files.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sandbox-escape
  - persistence
  - office-macro
  - macos
vendors:
  - Microsoft
products:
  - Microsoft Word
affected_os:
  - MacOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://objective-see.org/blog/blog_0x35.html
rules:
  - title: Office for Mac Sandbox Escape - LaunchAgent Creation
    description: Detects the creation of a LaunchAgent file by Microsoft Word, which is indicative of a sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1059.005
      - T1543.002
    data_sources:
      - file_event
      - macos
  - title: Office for Mac Sandbox Escape - launchd Process Creation
    description: Detects suspicious processes spawned by launchd from the user's LaunchAgents directory, which may indicate a sandbox escape attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.005
      - T1543.002
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

A weakness exists in Microsoft Office for macOS that allows an attacker to bypass the application's sandbox restrictions. By exploiting a faulty regular expression used for filtering temporary files, malicious actors can create files in arbitrary locations. Specifically, they can craft a launchd plist file in the user's `~/Library/LaunchAgents` directory. Upon user login, launchd will execute the plist, leading to arbitrary code execution outside the confines of the Office sandbox. This allows for persistence and potentially full system compromise. The technique was initially documented in a 2018 blog post detailing the exploitation of this vulnerability via a malicious Microsoft Word document and the Empire C2 framework. This bypass circumvents macOS sandbox protections and achieves persistence, giving attackers a reliable foothold.

## Attack Chain

1. The attacker delivers a malicious Microsoft Word document to the target user, likely through phishing.
2. The user opens the document, triggering a malicious macro.
3. The macro uses `Private Declare PtrSafe Function system Lib "libc.dylib" Alias "popen"` to execute shell commands.
4. The attacker leverages the sandbox exception for temporary files, which uses the regex `(^|/)~\$[^/]+$`.
5. The macro creates a malicious launchd plist file in `~/Library/LaunchAgents` with a filename matching the regex (e.g., `~$evil.plist`).
6. The plist file contains commands to execute a malicious payload, such as a Python script that downloads and executes a stager from a C2 server.
7. The user logs out and back in (or is forced to log out via `launchctl bootout gui/$UID`), causing launchd to execute the malicious plist.
8. The stager establishes a connection to the attacker's C2 server, providing the attacker with a fully functional agent outside the Office sandbox.

## Impact

Successful exploitation allows attackers to bypass the Microsoft Office sandbox on macOS, achieving persistence on the target system. This can lead to the installation of malware, data exfiltration, or further compromise of the network. The number of victims and specific sectors targeted are unknown, but any macOS user opening a malicious Office document is potentially at risk. If successful, the attacker gains an unrestricted agent session, circumventing intended security controls.

## Recommendation

*   Monitor for process creations originating from Microsoft Word that involve writing files to the `~/Library/LaunchAgents` directory with filenames matching the regex `(^|/)~\$[^/]+$` using the "Office for Mac Sandbox Escape - LaunchAgent Creation" Sigma rule.
*   Monitor for suspicious processes spawned by launchd, particularly those running from the `~/Library/LaunchAgents` directory using the "Office for Mac Sandbox Escape - launchd Process Creation" Sigma rule.
*   Review and restrict the use of macros in Microsoft Office, and implement policies to only allow signed macros from trusted sources.
*   Consider implementing additional endpoint detection and response (EDR) rules to detect and prevent the execution of malicious payloads downloaded by the stager.
