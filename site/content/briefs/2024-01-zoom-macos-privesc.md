---
title: Zoom macOS Client Privilege Escalation Vulnerability
slug: 2024-01-zoom-macos-privesc
description: Zoom's macOS client contains a local privilege escalation vulnerability that allows an unprivileged attacker to gain root privileges by subverting the runwithroot script, due to the insecure use of the deprecated AuthorizationExecuteWithPrivileges API.
date: "2024-01-03T14:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - privilege-escalation
  - macos
  - zoom
vendors:
  - Zoom
  - Apple
products:
  - Zoom Client for Mac
  - macOS Malware Removal Tool
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://objective-see.org/blog/blog_0x56.html
rules:
  - title: Detect Modification of Zoom runwithroot Script
    description: Detects modification of the Zoom runwithroot script in temporary directories, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - macos
  - title: Detect Security Authtrampoline Executing Suspicious Scripts
    description: Detects execution of scripts from user-writable temporary directories via security_authtrampoline, which may indicate a privilege escalation attempt
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

The Zoom macOS client, specifically version 4.6.8 (19178.0323) and earlier, contains a local privilege escalation vulnerability. This vulnerability stems from the insecure use of the deprecated AuthorizationExecuteWithPrivileges API. The Zoom installer copies a bash script named `runwithroot` to a user-writable temporary directory. A local, unprivileged attacker can subvert this script before it is executed as root, thereby escalating their privileges. The vulnerability requires a local foothold on the macOS system and relies on the installer or updater being executed. While Zoom has faced other security and privacy concerns, this particular flaw allows for a complete takeover of the system by a local attacker. This privilege escalation vulnerability poses a significant risk, particularly in environments where multiple users share a single macOS system or where malware may already have a limited foothold. Zoom patched this in version 4.6.9 (19273.0402).

## Attack Chain

1.  Attacker gains initial access to the macOS system via malware or other means.
2.  The Zoom installer package (Zoom.pkg) is executed, either by the user or automatically through an update.
3.  The macOS Installer copies the `runwithroot` script to a user-writable temporary directory, such as `/private/var/folders/v5/s530008n11dbm2n2pgzxkk700000gp/T/com.apple.install.v43Mcm4r/`.
4.  The attacker identifies the temporary directory and modifies the `runwithroot` script with malicious commands.
5.  The installer invokes the AuthorizationExecuteWithPrivileges API, prompting the user for administrator credentials if they are not already an administrator.
6.  The system executes `/usr/libexec/security_authtrampoline` with the `runwithroot` script as an argument.
7.  The `runwithroot` script, now containing malicious commands, executes with root privileges.
8.  The attacker achieves root-level access on the system, allowing them to perform any action they desire, such as installing malware, stealing data, or compromising other users.

## Impact

Successful exploitation of this vulnerability allows a local attacker to gain complete control over the affected macOS system. The attacker can install persistent backdoors, steal sensitive data, or compromise other user accounts on the system. While the report does not specify the number of victims, the widespread use of Zoom makes this a high-impact vulnerability. Sectors targeted could include any organization using Zoom on macOS, potentially leading to significant data breaches or system compromise.

## Recommendation

*   Upgrade Zoom to version 4.6.9 (19273.0402) or later to patch the privilege escalation vulnerability.
*   Deploy the Sigma rule `Detect Modification of Zoom runwithroot Script` to detect attempts to modify the vulnerable script.
*   Monitor for the execution of `security_authtrampoline` with arguments pointing to user-writable directories, as indicated in the analysis of the AuthorizationExecuteWithPrivileges API usage.
*   Enable process monitoring to detect the execution of scripts or binaries from temporary directories, which can indicate exploitation attempts.
*   Consider disabling or restricting the use of the AuthorizationExecuteWithPrivileges API where possible, as recommended by Apple.
