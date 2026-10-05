---
title: Twine 2 Cross-Site Scripting to Remote Code Execution
slug: 2026-10-twine-xss-rce
description: Twine 2 desktop versions through 2.12.0 contain a cross-site scripting flaw in the importStories function that can be leveraged via an IPC bridge to achieve arbitrary code execution.
date: "2026-10-05T00:56:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:twine:twine:*:*:*:*:*:*:*:*
tags:
  - cross-site-scripting
  - rce
  - client-side-vulnerability
vendors:
  - Twine
products:
  - Twine (<= 2.12.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can craft a story file whose script calls the twineElectron openWithScratchFile IPC bridge to write and open a .bat file, executing code as the user.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.004
    technique_name: 'Server Software Component: Web Shell'
    evidence: Twine 2 desktop through 2.12.0 contains a cross-site scripting vulnerability in importStories() that executes markup from imported story files in the editor window.
    confidence_band: high
cves:
  - id: CVE-2026-105220
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105220
rules:
  - title: Detect Suspicious Twine Process Spawning Command Interpreter
    description: Detects the Twine desktop application spawning a command interpreter, which may indicate the execution of a malicious .bat file via the openWithScratchFile IPC bridge.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy process monitoring rule to detect Twine spawning cmd.exe
      owner: Detection Engineering
      due: 24h
      evidence: Rule provided in brief
  mitigation_plan:
    - priority: immediate
      action: Restrict importing untrusted story files
      owner: IT Operations
      addresses: CVE-2026-105220
      evidence: Source details exploit mechanism via story file import
---

Twine 2 desktop application versions up to 2.12.0 are vulnerable to a cross-site scripting (XSS) vulnerability within the importStories() function. An attacker can craft a malicious story file containing embedded JavaScript that, when imported into the editor, executes within the application context. This vulnerability is escalated through the misuse of the 'twineElectron' IPC bridge, specifically the 'openWithScratchFile' method. By manipulating this bridge, an attacker can force the application to write and subsequently execute an arbitrary .bat file on the host operating system. This allows for code execution under the privileges of the user running the Twine desktop application. This flaw poses a significant risk to users who import untrusted story files from external sources, as the malicious code triggers upon file processing within the editor environment.

## Impact

Successful exploitation allows for arbitrary code execution on the user's machine. This can lead to full compromise of the user account, potentially resulting in data theft, persistence establishment, or lateral movement within the network. Users of the Twine desktop application who frequently collaborate or import content from community repositories are at the highest risk of being targeted via malicious story files.

## Recommendation

Prioritized actions for security teams to address CVE-2026-105220:

* Upgrade the Twine desktop application to a version beyond 2.12.0 immediately as it becomes available to patch the importStories() XSS vulnerability.
* Implement an organizational policy to restrict the importing of story files from untrusted or public third-party repositories until the application is patched.
* Use endpoint monitoring to detect unusual process lineage where the Twine application process (Twine.exe) spawns cmd.exe or batch file executors.
