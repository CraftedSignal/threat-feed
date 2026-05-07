---
title: Mac Adware Injecting Malicious JavaScript via Obfuscated Python Script
slug: 2026-05-mac-adware-python
description: A Mac adware, likely a component of OSX.Pirrit, uses multiple layers of obfuscation, including base64 encoding, zlib compression, and variable renaming, to evade detection and inject malicious JavaScript from hxxps://1049434604.rsc.cdn77.org/ij1.min.js.
date: "2026-05-07T07:33:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - adware
  - macos
  - python
  - javascript_injection
vendors:
  - Apple
  - MacPaw
products:
  - CleanMyMac X
  - OSX.Pirrit
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
references:
  - https://objective-see.org/blog/blog_0x3F.html
iocs:
  - type: url
    value: https://1049434604.rsc.cdn77.org/ij1.min.js
ioc_counts:
  url: 1
rules:
  - title: Detect JavaScript Injection via osascript
    description: Detects the execution of osascript with arguments indicative of JavaScript injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
  - title: Detect Adware Python Script Execution from Library
    description: Detects execution of python scripts from user Library folders, often used for adware persistence
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

This brief details the analysis of a persistent Mac adware sample, potentially a component of the OSX.Pirrit family, first brought to light by Paul Taykalo of MacPaw. The adware employs multiple layers of obfuscation, including compiled Python bytecode, base64 encoding, zlib compression, and variable renaming, to evade traditional antivirus detection. Initial analysis of the VtZkT sample showed it was initially undetected by most AV engines on VirusTotal. The adware persists via a launch item, executing a Python script that ultimately injects malicious JavaScript into web pages. The analysis highlights the techniques used to deobfuscate the code and reveal the adware's functionality, including the URL from which it downloads malicious JavaScript: hxxps://1049434604.rsc.cdn77.org/ij1.min.js.

## Attack Chain

1.  The adware is likely installed via shareware installers or trojanized applications, such as fake Adobe Flash installers.
2.  A bash script (CqfeP) is persisted as a launch item to ensure the adware is automatically started each time the user logs into their Mac.
3.  The bash script changes directory to `/Users/<user>/Library/search.amp`.
4.  The bash script executes a compiled Python script (5mLen) with the `f=` parameter specifying another file (6bLJC).
5.  The 5mLen script decompresses and decodes the contents of 6bLJC, which contains base64 encoded and XORed data.
6.  The decoded script replaces placeholders like `pid_REPLACE`, `script_to_inject_REPLACE`, and `MID_REPLACE` with values including a PID flag, the URL `hxxps://1049434604.rsc.cdn77.org/ij1.min.js`, and a machine identifier.
7.  The script executes the resulting JavaScript via `osascript`, injecting it into the current user's web browser.
8.  The injected JavaScript likely displays advertisements or redirects user traffic for malicious purposes.

## Impact

The adware injects malicious JavaScript into web browsers, potentially leading to unwanted advertisements, browser redirects, data theft, or other malicious activities. While the exact scope of the campaign is unknown, the use of obfuscation techniques suggests a deliberate attempt to evade detection and target a wide range of Mac users. The injected JavaScript can compromise user experience and potentially lead to further malware infections.

## Recommendation

*   Monitor for the execution of `osascript` with suspicious arguments, specifically those containing injected JavaScript, using the Sigma rule "Detect JavaScript Injection via osascript".
*   Block network connections to `1049434604.rsc.cdn77.org` at the firewall or DNS resolver based on the IOC identified in this brief.
*   Monitor for the creation and execution of files within the `~/Library/search.amp` directory.
*   Inspect shell scripts executed from user LaunchAgents for suspicious python calls.
