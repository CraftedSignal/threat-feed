---
title: Remote Code Execution in MOOS-IvP iSay
slug: 2026-09-moos-ivp-rsce
description: The iSay component in MOOS-IvP through 24.8.1 is vulnerable to remote code execution because it passes unsanitized SAY_MOOS variable content directly to a shell, allowing command injection via backticks or substitution syntax.
date: "2026-09-03T23:24:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:moos-ivp:isay:*:*:*:*:*:*:*:*
vendors:
  - MOOS-IvP
products:
  - iSay (<= 24.8.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The SAY_MOOS variable handler passes unsanitized text to a shell command.
    confidence_band: high
cves:
  - id: CVE-2026-85425
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85425
rules:
  - title: Detect iSay Suspicious Shell Execution
    description: Detects the iSay process spawning a shell, which indicates potential command injection exploitation of CVE-2026-85425.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect suspicious shell execution by iSay.
      owner: Detection Engineering
      due: 24h
      evidence: Source reporting of command execution in iSay.
  mitigation_plan:
    - priority: immediate
      action: Monitor network traffic to MOOSDB to identify anomalous message publication.
      owner: SOC
      addresses: CVE-2026-85425
      evidence: Remote exploitation vector confirmed.
---

The MOOS-IvP (Mission Oriented Operating Suite - Interval Programming) project contains a critical security vulnerability in its iSay component. This component, often used for text-to-speech or notification messaging within the MOOS environment, fails to adequately sanitize input provided through the SAY_MOOS variable. As of version 24.8.1 and earlier, the application passes the contents of this variable directly into a system shell execution context. 

An attacker capable of publishing messages to the MOOS community database (DB) can manipulate the SAY_MOOS variable to include shell command substitution characters, such as backticks or "$( )" syntax. When the iSay process parses these malformed messages, the shell interprets the injected sequences as commands, leading to arbitrary code execution under the privileges of the iSay process. This vulnerability is particularly relevant in autonomous vehicle and robotic systems where MOOS-IvP is deployed to facilitate inter-process communication and task coordination.

## Attack Chain

1. Attacker gains network access to the MOOS community database (MOOSDB) via the configured MOOS port.
2. Attacker crafts a malicious MOOS message containing shell command injection syntax (e.g., `SAY_MOOS = "test \`whoami\`"`).
3. Attacker publishes the crafted message to the MOOSDB using standard MOOS communication protocols.
4. The iSay process, subscribed to updates on the SAY_MOOS variable, receives the malicious payload.
5. The iSay process passes the payload string to a system execution function (e.g., popen or system) without sanitization.
6. The underlying system shell executes the attacker's injected command.
7. Attacker achieves remote code execution with the permissions of the iSay application.

## Impact

Successful exploitation allows an attacker to execute arbitrary code on the host running the iSay process. Given that MOOS-IvP is frequently utilized in unmanned robotic and autonomous surface vehicles, this could lead to full system compromise, exfiltration of telemetry data, or disruption of mission-critical control software.

## Recommendation

* Patch the MOOS-IvP environment by updating to a version beyond 24.8.1 once the vendor provides a remediation.
* Implement strict input validation within the MOOSDB gateway to restrict the characters allowed in the SAY_MOOS variable.
* Monitor the iSay process for anomalous child process spawning, such as /bin/sh or /bin/bash executions that originate from the iSay binary.
* Segment the network to ensure that only authorized nodes can publish to the MOOSDB.
