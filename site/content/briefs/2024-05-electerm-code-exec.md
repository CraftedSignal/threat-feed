---
title: Electerm Arbitrary Code Execution via Crafted URI or CLI Arguments
slug: 2024-05-electerm-code-exec
description: Electerm versions 3.0.6 through 3.8.14 are vulnerable to arbitrary local code execution via crafted electerm:// URIs or command-line arguments, requiring a user to click a malicious link or open a malicious shortcut file.
date: "2026-05-08T18:46:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-execution
  - protocol-handler
  - electerm
vendors:
  - Electerm
products:
  - Electerm (>= 3.0.6, < 3.8.15)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-43944
references:
  - https://github.com/advisories/GHSA-mpm8-cx2p-626q
  - https://github.com/Curly-Haired-Baboon
  - https://github.com/electerm/electerm/releases
  - https://github.com/electerm/electerm/commit/8a6a17951e96d715f5a231532bbd8303fe208700
  - https://github.com/electerm/electerm/commit/a79e06f4a1f0ac6376c3d2411ef4690fa0377742
rules:
  - title: Detect Electerm URI Protocol Handler Abuse
    description: Detects CVE-2026-43944 exploitation — execution of electerm with electerm:// URI protocol handler
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Electerm Malicious opts Argument
    description: Detects CVE-2026-43944 exploitation — execution of electerm with a suspicious opts argument
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Electerm, a free and open-source terminal/ssh/sftp client, is vulnerable to arbitrary code execution. Versions 3.0.6 through 3.8.14 are susceptible to this vulnerability. An attacker can exploit this by crafting a malicious `electerm://` URI or by crafting a shortcut/command that launches electerm with attacker-controlled `--opts` arguments. Successful exploitation requires a user to click the malicious link or open the malicious shortcut file. This vulnerability allows attackers to execute arbitrary code on the victim's machine, potentially leading to system compromise, data theft, or other malicious activities. The vulnerability was reported by Curly-Haired-Baboon.

## Attack Chain

1.  The attacker crafts a malicious `electerm://` URI or a shortcut/command containing malicious `--opts` arguments.
2.  The attacker distributes the malicious URI or shortcut/command to the victim via social engineering or other means.
3.  The victim clicks on the malicious `electerm://` URI or opens the malicious shortcut/command.
4.  Electerm is launched with the attacker-controlled parameters.
5.  Due to insufficient validation of the input, the attacker's payload is processed by Electerm.
6.  The attacker's payload executes arbitrary code on the victim's machine.
7.  The attacker gains control of the compromised system, enabling them to perform malicious activities.

## Impact

Successful exploitation of this vulnerability can lead to arbitrary code execution on the victim's machine. This can result in a wide range of malicious activities, including but not limited to, system compromise, data theft, installation of malware, and denial of service. Given the nature of Electerm as a terminal client, attackers could potentially gain access to sensitive credentials and systems managed through the application.

## Recommendation

*   Upgrade Electerm to version 3.8.15 or later to patch CVE-2026-43944.
*   Disable or unregister electerm protocol handlers (Deep Link settings) as a workaround.
*   Avoid clicking `electerm://` links from untrusted sources.
*   Refrain from running electerm with untrusted `--opts` arguments or opening `.lnk` / `.desktop` files from untrusted sources.
*   Deploy the Sigma rule "Detect Electerm URI Protocol Handler Abuse" to identify attempts to exploit this vulnerability by monitoring process execution that involves the electerm protocol.
