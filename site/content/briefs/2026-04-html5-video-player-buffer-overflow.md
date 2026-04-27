---
title: HTML5 Video Player 1.2.5 Local Buffer Overflow Vulnerability
slug: 2026-04-html5-video-player-buffer-overflow
description: HTML5 Video Player version 1.2.5 is vulnerable to a local buffer overflow, allowing attackers to execute arbitrary code by providing an oversized key code string through the Help Register dialog.
date: "2026-04-12T13:16:31Z"
severities:
  - high
tags:
  - buffer-overflow
  - code-execution
  - html5-video-player
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2019-25689
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25689
  - http://www.html5videoplayer.net/download.html
  - https://www.exploit-db.com/exploits/46279
  - https://www.vulncheck.com/advisories/html5-video-player-local-buffer-overflow-non-seh
rules:
  - title: Suspicious Child Process of HTML5 Video Player
    description: Detects suspicious child processes spawned by HTML5 Video Player, indicating potential exploitation of CVE-2019-25689.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
      - T1059.005
      - T1569.002
    data_sources:
      - process_creation
      - windows
  - title: HTML5 Video Player Help Dialog Open
    description: Detects the opening of the Help Register dialog in HTML5 Video Player, a prerequisite for exploiting CVE-2019-25689.  This rule is intended as a possible early warning, not definitive exploitation.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

HTML5 Video Player version 1.2.5 is susceptible to a local buffer overflow vulnerability (CVE-2019-25689). An attacker can exploit this flaw by crafting a malicious payload exceeding 997 bytes and pasting it into the "KEY CODE" field located within the Help Register dialog. Successful exploitation leads to arbitrary code execution within the context of the application, as demonstrated by spawning a calculator process. This vulnerability, discovered in 2019 but only recently published…
