---
title: File Browser Pre-Authentication Command Injection via Authentication Hook (CVE-2026-54088)
slug: 2026-07-filebrowser-preauth-rce
description: The Hook Authentication feature in File Browser (versions up to 2.63.5) is vulnerable to a pre-authentication command injection flaw (CVE-2026-54088), allowing an unauthenticated remote attacker to execute arbitrary OS commands by injecting shell metacharacters into login fields during `os.Expand` operations, leading to critical Remote Code Execution (RCE) without valid credentials.
date: "2026-07-10T19:35:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - web-application
vendors:
  - File Browser
products:
  - File Browser (<= 2.63.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can inject shell metacharacters in the username or password field at the login screen, causing the server to execute arbitrary OS commands before any authentication takes place. This is a critical pre-authentication RCE.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'The attacker''s command runs with the privileges of the File Browser process -- without needing a valid account or password. ... The shell will execute: sh -c ''id ; echo injected'''
    confidence_band: high
cves:
  - id: CVE-2026-54088
    epss: 0.00533
references:
  - https://github.com/advisories/GHSA-m93h-4hw7-5qcm
rules:
  - title: Detect CVE-2026-54088 Exploitation - File Browser Command Injection
    description: Detects exploitation of CVE-2026-54088 where File Browser's Hook Authentication feature executes arbitrary commands due to shell metacharacter injection in username/password fields, observable as unusual child processes of the filebrowser application.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

The File Browser application, specifically versions up to and including 2.63.5, contains a critical pre-authentication remote code execution (RCE) vulnerability, identified as CVE-2026-54088. This flaw resides within its Hook Authentication feature, where the application delegates login verification to an external shell command. User-supplied credentials, particularly the username and password, are interpolated into this command string using `os.Expand` without proper sanitization. Consequently, an unauthenticated remote attacker can inject shell metacharacters into the login fields, such as the username or password. This manipulation causes the server to execute arbitrary operating system commands with the privileges of the File Browser process before any authentication can take place. The vulnerability allows for complete server compromise, making it a high-priority threat for organizations utilizing affected File Browser instances, especially those exposed to the internet.

## Attack Chain

1. An administrator configures File Browser's Hook Authentication feature, setting up an external shell command for login verification (e.g., `sh -c "test $USERNAME = 'admin'"`).
2. An unauthenticated attacker sends a crafted login request to the File Browser instance via HTTP (e.g., using `curl` or the web UI).
3. The attacker injects shell metacharacters (e.g., `; id #`) into the username field of the login request.
4. The File Browser application's `auth/hook.go` `HookAuth.RunCommand` function processes the login attempt.
5. Inside `RunCommand`, the `os.Expand` function performs a plain text substitution, embedding the attacker's malicious input directly into the configured shell command string.
6. The manipulated command, now containing the injected shell commands, is executed by the server (e.g., `sh -c "test ; id # = 'admin'"`).
7. The attacker's arbitrary command (e.g., `id`) is executed on the server with the privileges of the `filebrowser` process.
8. The attacker achieves pre-authentication remote code execution, enabling data exfiltration, persistent backdoor installation, or lateral movement.

## Impact

An unauthenticated remote attacker can achieve full control over the server hosting the File Browser instance. This pre-authentication RCE means compromise requires no prior foothold, no valid credentials, and a single crafted HTTP request. Successful exploitation leads to severe consequences, including complete server compromise, data exfiltration, installation of persistent backdoors, and potential lateral movement into internal networks. Any internet-facing File Browser deployment with Hook Authentication enabled is at critical risk of full system takeover.

## Recommendation

* Patch CVE-2026-54088 immediately by upgrading File Browser to a version greater than 2.63.5.
* If immediate patching is not possible, disable the Hook Authentication feature in File Browser.
* Deploy the Sigma rule "Detect CVE-2026-54088 Exploitation - File Browser Command Injection" to your SIEM and monitor for `process_creation` events, specifically unusual child processes spawned by the `filebrowser` executable.
* Enable `process_creation` logging for Linux systems to ensure visibility for the detection rule.
