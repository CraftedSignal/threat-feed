---
title: Twitch Studio Privilege Escalation Vulnerability (CVE-2024-14032)
slug: 2026-04-twitch-privesc
description: Twitch Studio version 0.114.8 and prior contains a privilege escalation vulnerability (CVE-2024-14032) that allows local attackers to execute arbitrary code as root by exploiting an unprotected XPC service, enabling them to overwrite system files and achieve full system compromise.
date: "2026-04-06T16:16:26Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - cve-2024-14032
  - twitch
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2024-14032
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-14032
  - https://www.vulncheck.com/advisories/twitch-studio-launcherhelper-xpc-missing-authorization-to-root-file-write
rules:
  - title: Detect Suspicious File Overwrite
    description: Detects potential exploitation of CVE-2024-14032 by monitoring for file overwrites in critical system directories by unexpected processes.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - macos
  - title: Detect Twitch Studio Helper Tool Execution
    description: Detects execution of Twitch Studio Helper Tool, which could be related to exploitation of CVE-2024-14032.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

Twitch Studio, specifically versions 0.114.8 and earlier, is vulnerable to a critical privilege escalation flaw (CVE-2024-14032). This vulnerability resides within the application's privileged helper tool and stems from an unprotected XPC service. A local attacker can exploit this vulnerability to execute arbitrary code with root privileges. The vulnerability allows the attacker to leverage the `installFromPath:toPath:withReply:` method to overwrite sensitive system files and privileged binaries, ultimately leading to complete system compromise. It is important to note that Twitch Studio was discontinued in May 2024, meaning it is no longer actively maintained and patched. This vulnerability poses a significant risk to systems where the vulnerable software remains installed.

## Attack Chain

1.  The attacker gains initial local access to a system with Twitch Studio 0.114.8 or prior installed.
2.  The attacker identifies the vulnerable XPC service within the Twitch Studio privileged helper tool.
3.  The attacker crafts a malicious XPC message targeting the `installFromPath:toPath:withReply:` method.
4.  The attacker leverages the unprotected XPC service to send the crafted message.
5.  The vulnerable method executes, allowing the attacker to specify a source file and a destination path.
6.  The attacker chooses a malicious file as the source and a critical system file or privileged binary as the destination (e.g., `/usr/bin/sudo`, `/etc/passwd`).
7.  The vulnerable method overwrites the targeted system file with the attacker-controlled content.
8.  The attacker executes the overwritten system file, now containing malicious code, with root privileges, achieving full system compromise.

## Impact

Successful exploitation of CVE-2024-14032 allows a local attacker to gain complete control of the affected system. This includes the ability to read, modify, or delete any data, install malware, and pivot to other systems on the network. While the exact number of affected systems is unknown, any machine with a vulnerable version of Twitch Studio installed is at risk. Given that Twitch Studio was a popular streaming application, the potential impact could be significant if unpatched installations remain.

## Recommendation

*   Identify systems with Twitch Studio version 0.114.8 or earlier installed. Since Twitch Studio was discontinued in May 2024, consider uninstalling the application to eliminate the vulnerability.
*   Monitor for unexpected file writes to critical system directories, such as `/usr/bin`, `/usr/sbin`, `/etc`, and `/System/Library`, which could indicate exploitation attempts. Deploy the Sigma rule `Detect Suspicious File Overwrite` to identify potential exploitation.
*   Implement application control policies to prevent the execution of unauthorized or modified binaries.
