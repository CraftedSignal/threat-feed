---
title: TidGi Desktop Remote Code Execution via Malicious TiddlyWiki Repository Import
slug: 2026-07-tidgi-rce
description: A critical remote code execution (RCE) vulnerability exists in TidGi Desktop through version 0.13.0, allowing attackers to execute arbitrary code with full Node.js access by tricking victims into importing a specially crafted TiddlyWiki Git repository, leveraging the automatic execution of 'startup' modules during the wiki boot sequence.
date: "2026-07-14T20:17:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - initial-access
  - execution
  - windows
  - macos
  - linux
vendors:
  - Lin Onetwo
products:
  - TidGi Desktop 0.13.0
affected_os:
  - Windows
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: 'Only user interaction: click ''Add Workspace'' → select folder/URL → confirm. Attacker creates a malicious TiddlyWiki repository.'
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Full Node.js access. `require('child_process').execSync('calc');` successfully executed arbitrary shell commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: '`require(''child_process'').execSync(''touch /tmp/TidGi-RCE-PoC.txt'');` successfully executed arbitrary shell commands on macOS.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9hc2-hjx8-q6pv
iocs:
  - type: filename
    value: /tmp/TidGi-RCE-PoC.txt
  - type: filename
    value: tiddlers/$__plugins__poc__startup.js.tid
  - type: code
    value: exports.startup = function() { require('child_process').execSync('calc'); };
  - type: code
    value: exports.startup = function() { require('child_process').execSync('touch /tmp/TidGi-RCE-PoC.txt'); console.log('STARTUP_EXECUTED'); };
ioc_counts:
  code: 2
  filename: 2
rules:
  - title: Detect TidGi Desktop RCE Payload Execution
    description: Detects suspicious process creation by TidGi Desktop, indicative of successful remote code execution through malicious TiddlyWiki repository import. This rule looks for common command execution utilities spawned by the TidGi Desktop process.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.003
      - T1204.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

TidGi Desktop, up to and including version 0.13.0, is affected by a critical remote code execution vulnerability. This flaw can be exploited when a user imports a specially crafted TiddlyWiki repository. The vulnerability stems from TiddlyWiki's module system, which automatically discovers and executes JavaScript code embedded in `.tid` files placed in the wiki's `tiddlers/` directory. Specifically, `.tid` files are auto-loaded into the wiki store, modules with `module-type: startup` are automatically registered, and their `exports.startup()` function is executed during the wiki's boot sequence with full Node.js `require()` access. This allows an attacker to execute arbitrary commands on the victim's system, confirmed on macOS with TiddlyWiki 5.4.0 and Node.js v26. No authentication is required beyond a single user interaction to import the malicious repository, making it a high-impact vulnerability.

## Attack Chain

1. An attacker crafts a malicious TiddlyWiki repository containing a `.tid` file with `module-type: startup` and JavaScript code in the `exports.startup` function (e.g., `require('child_process').execSync('calc');`).
2. The victim is enticed to import the malicious repository into TidGi Desktop, typically by clicking "Add Workspace" and selecting the attacker-controlled Git repository or local folder.
3. TidGi Desktop initiates the wiki boot sequence, which involves `$tw.boot.startup()`.
4. During `loadStartup()`, the `loadTiddlersNode()` function reads all `.tid` files from the filesystem, including the attacker's malicious file, and adds them to the wiki store via `wiki.addTiddlers()`.
5. Subsequently, `execStartup()` calls `defineTiddlerModules()`, which iterates through all tiddlers in the store. The attacker's tiddler, having `module-type: startup`, is registered as an executable module.
6. The boot sequence proceeds to `forEachModuleOfType("startup", ...)`, collecting all registered "startup" modules, including the attacker's.
7. Finally, `executeNextStartupTask()` calls the `exports.startup()` function of the collected modules without platform restrictions, leading to the execution of the attacker's JavaScript code with full Node.js privileges.
8. Arbitrary commands, such as launching `calc.exe` or creating files, are executed on the victim's operating system.

## Impact

Successful exploitation of this vulnerability leads to critical consequences, including full Node.js access for the attacker, enabling remote code execution on the victim's machine. Attackers can leverage this access to perform arbitrary file reads and writes, establish reverse shells using Node.js's `net` module, and establish persistence by writing to startup scripts or other system mechanisms. The vulnerability affects Windows, macOS, and Linux systems and requires only a single user interaction (importing the repository). Given that TidGi Desktop is a personal knowledge base and note-taking application, a compromise could lead to significant data exfiltration, system damage, or further lateral movement within an affected environment.

## Recommendation

* Enable comprehensive `process_creation` logging across all endpoints running TidGi Desktop to detect unusual child processes spawned by Node.js or TidGi-Desktop, leveraging the Sigma rule provided in this brief.
* Monitor `file_event` logs for suspicious file creations, especially in temporary directories (`/tmp` on Linux/macOS, `%TEMP%` on Windows), originating from the TidGi-Desktop process or its child processes.
* Educate users about the risks of importing untrusted repositories or files into applications like TidGi Desktop.
* Implement application whitelisting solutions to restrict execution of unknown or untrusted executables, particularly those launched as child processes by applications like TidGi Desktop.
