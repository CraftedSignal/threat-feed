---
title: HKUDS OpenHarness Remote Code Execution via /bridge Slash Command (CVE-2026-7551)
slug: 2026-05-openharness-rce
description: HKUDS OpenHarness contains a remote code execution vulnerability (CVE-2026-7551) in the /bridge slash command, allowing remote attackers to execute arbitrary operating system commands by injecting malicious commands via the /bridge spawn command, leading to unauthorized shell access and data exposure.
date: "2026-04-30T22:17:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - injection
vendors:
  - HKUDS
products:
  - OpenHarness
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7551
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7551
rules:
  - title: Detect OpenHarness Suspicious Process Execution via Bridge
    description: Detects suspicious process execution originating from the OpenHarness process, indicating potential exploitation of CVE-2026-7551.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenHarness Suspicious Process Execution via Bridge Windows
    description: Detects suspicious process execution originating from the OpenHarness process, indicating potential exploitation of CVE-2026-7551.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

HKUDS OpenHarness is vulnerable to a remote code execution flaw (CVE-2026-7551) affecting the /bridge slash command. This vulnerability permits remote attackers, who are authorized by the OpenHarness configuration, to execute arbitrary operating system commands on the host system. The attack leverages the /bridge spawn command, which, when supplied with attacker-controlled command text, is processed by the bridge session manager and executed through a shared shell subprocess. This execution context grants attackers the ability to spawn shell sessions with the privileges of the OpenHarness process user, potentially exposing local files, credentials, workspace state, and repository contents. Successful exploitation results in a complete compromise of the OpenHarness instance.

## Attack Chain

1.  Attacker identifies an accessible OpenHarness instance with the vulnerable /bridge slash command enabled.
2.  The attacker authenticates or gains access to a communication channel (e.g., chat application) accepted by OpenHarness.
3.  The attacker crafts a malicious /bridge spawn command containing OS commands to be executed.
4.  The attacker sends the crafted /bridge spawn command to the OpenHarness instance via the configured communication channel.
5.  OpenHarness processes the /bridge command and forwards the attacker-controlled command text to the bridge session manager.
6.  The bridge session manager executes the injected OS commands through a shared shell subprocess.
7.  The attacker gains a shell session with the privileges of the OpenHarness process user.
8.  The attacker accesses local files, credentials, workspace state, and repository contents, potentially exfiltrating sensitive data or establishing persistence.

## Impact

Successful exploitation of CVE-2026-7551 allows attackers to execute arbitrary operating system commands on the OpenHarness server. This grants them the ability to spawn shell sessions as the OpenHarness process user, which can lead to the exposure of sensitive information such as local files, credentials, workspace state, and repository contents. The impact of this vulnerability is significant, potentially allowing for complete system compromise and data exfiltration, but the exact number of victims is currently unknown.

## Recommendation

*   Apply available patches or updates provided by HKUDS to address CVE-2026-7551 on all OpenHarness instances.
*   Implement input validation and sanitization on the /bridge slash command to prevent the injection of malicious OS commands.
*   Monitor process creation events for suspicious shell executions originating from the OpenHarness process using the provided Sigma rule.
*   Restrict network access to the OpenHarness server to only authorized users and systems.
*   Review OpenHarness configurations to ensure that only trusted communication channels are accepted.
