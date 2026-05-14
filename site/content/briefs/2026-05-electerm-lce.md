---
title: Electerm Local Code Execution via Single-Instance Socket (CVE-2026-45353)
slug: 2026-05-electerm-lce
description: Electerm versions 3.0.6 through 3.8.8 are vulnerable to local code execution (CVE-2026-45353) where a same-user process can send a JSON payload to the application's single-instance socket/pipe, leading to arbitrary tab creation and local process spawning.
date: "2026-05-14T20:35:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - local code execution
  - vulnerability
vendors:
  - electerm
products:
  - electerm (>= 3.0.6, <= 3.8.8)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Inter-Process Communication
references:
  - https://github.com/advisories/GHSA-7p5m-v798-f8vv
  - https://github.com/Curly-Haired-Baboon
  - https://github.com/electerm/electerm/releases
rules:
  - title: Detect Electerm Malicious Payload Delivery
    description: Detects CVE-2026-45353 exploitation — Suspicious processes attempting to interact with Electerm's single-instance socket/pipe using interprocess communication.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1559.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Electerm Suspicious Child Processes
    description: Detects CVE-2026-45353 exploitation — Electerm spawning suspicious child processes, potentially indicating code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1559.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Electerm versions 3.0.6 through 3.8.8 are susceptible to a local code execution vulnerability (CVE-2026-45353) due to improper handling of inter-process communication. The single-instance feature of Electerm uses a socket or named pipe to communicate between instances of the application. An attacker with local access to the same user account can send a malicious JSON payload to this socket, bypassing intended security controls. This payload can instruct Electerm to create new tabs or execute arbitrary local processes, effectively granting the attacker code execution within the context of the Electerm application. This vulnerability impacts single-instance installations of Electerm and could lead to privilege escalation or data compromise if exploited.

## Attack Chain

1. The attacker identifies the Electerm single-instance socket/pipe.
2. The attacker crafts a malicious JSON payload designed to trigger code execution. This payload leverages Electerm's inter-process communication mechanism.
3. The attacker uses a separate process running under the same user account to send the malicious JSON payload to the Electerm socket/pipe.
4. Electerm receives the payload and, due to insufficient validation, processes the malicious instructions.
5. The malicious payload instructs Electerm to create a new tab.
6. The creation of the new tab triggers the execution of attacker-controlled code within the Electerm process.
7. The attacker-controlled code spawns a local process. This process could be a reverse shell, a data exfiltration tool, or any other arbitrary executable.
8. The attacker gains control of the spawned process, achieving local code execution.

## Impact

Successful exploitation of CVE-2026-45353 allows a local attacker to execute arbitrary code within the context of the Electerm application. This can lead to a variety of malicious outcomes, including privilege escalation, data theft, and system compromise. The impact is limited to single-instance installations of Electerm. If successfully exploited, an attacker can potentially gain full control over the user's session and sensitive data accessible by Electerm.

## Recommendation

*   Upgrade Electerm to a version greater than 3.8.8 to patch CVE-2026-45353, as indicated by the patch commit [https://github.com/electerm/electerm/commit/0599e67069b00e376a2e962649aaad6096e63507](https://github.com/electerm/electerm/commit/0599e67069b00e376a2e962649aaad6096e63507).
*   Deploy the Sigma rule "Detect Electerm Malicious Payload Delivery" to detect suspicious processes attempting to interact with Electerm's single-instance socket.
*   Monitor process creation events for unexpected child processes spawned by Electerm, leveraging the "Detect Electerm Suspicious Child Processes" Sigma rule.
