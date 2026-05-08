---
title: Electerm Arbitrary Protocol Execution Vulnerability
slug: 2024-07-electerm-rce
description: Electerm versions 3.8.15 and earlier are vulnerable to arbitrary code execution due to improper validation of URLs, allowing attackers to execute commands by tricking users into clicking malicious links in the terminal.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - terminal
  - protocol handler
vendors:
  - electerm
products:
  - electerm (<= 3.8.15)
affected_os:
  - Windows 10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2026-43941
    cvss: 9.6
references:
  - https://github.com/advisories/GHSA-fwf6-j56g-m97c
  - https://github.com/electerm/electerm
  - https://github.com/electerm/electerm/security
rules:
  - title: Detect Electerm Suspicious URI Invocation
    description: Detects CVE-2026-43941 exploitation — spawning of processes with unusual protocol handlers potentially triggered by Electerm's `shell.openExternal`
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Electerm file:// URI usage
    description: Detects CVE-2026-43941 exploitation — Attempts to use file:// protocol handler to access local files from electerm
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Electerm, a cross-platform terminal application, is vulnerable to an arbitrary protocol execution vulnerability (CVE-2026-43941) in versions 3.8.15 and earlier. This flaw stems from the application's failure to properly validate URLs passed to the `shell.openExternal` function. An attacker who can control terminal output, such as through a compromised SSH server or a malicious plugin, can inject a crafted URI into the terminal. If a user clicks on this malicious link, Electerm will execute it using the operating system's default protocol handler, potentially leading to code execution, data exfiltration, or other malicious activities. This vulnerability requires user interaction (clicking the link) to be exploited.

## Attack Chain

1.  Attacker compromises a remote SSH server or injects malicious content into terminal output.
2.  The attacker crafts a malicious URI containing a dangerous protocol handler like `ms-msdt:`, `search-ms:`, or `file://`.
3.  The malicious URI is printed to the Electerm terminal connected to the compromised SSH server.
4.  The victim, using Electerm, views the terminal output containing the malicious URI.
5.  The victim clicks on the malicious URI hyperlink in the Electerm terminal.
6.  Electerm's `shell.openExternal` function executes the URI without proper validation.
7.  The operating system's default protocol handler is invoked, executing the attacker's payload (e.g., code execution via `ms-msdt:`, NTLM hash leak via `file://`).
8.  Attacker achieves arbitrary code execution or exfiltrates sensitive information.

## Impact

Successful exploitation of this vulnerability (CVE-2026-43941) could allow an attacker to execute arbitrary code on a victim's machine. This could lead to complete system compromise, data theft, or the installation of malware. The vulnerability affects all Electerm users who interact with untrusted terminal outputs. The number of potential victims is dependent on Electerm's user base. If successfully exploited, an attacker gains the privileges of the user running Electerm.

## Recommendation

*   Deploy the Sigma rule "Detect Electerm Suspicious URI Invocation" to detect attempts to exploit CVE-2026-43941 by monitoring process creations with unusual protocol handlers (see rule definition below).
*   Apply the workaround to disable hyperlink rendering in electerm's terminal settings until a patch is available.
*   Monitor the electerm GitHub releases and security page for an update addressing this issue.
