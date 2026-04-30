---
title: Detection of Python Base64 Encoded Execution on Linux
slug: 2024-01-python-base64-linux
description: This brief focuses on detecting the execution of Python one-liners utilizing base64 decoding functions on Linux systems, a technique employed by malicious actors to obfuscate and execute payloads, thereby evading traditional security measures.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - defense-evasion
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://docs.python.org/3/library/base64.html
  - https://www.virustotal.com/gui/file/bc43e925d7b4b74319f6e74e836a96f1997ba404e14ac566cf12a21e9da463db/behavior
  - https://cloud.google.com/blog/topics/threat-intelligence/cybercriminals-weaponize-fake-ai-websites
rules:
  - title: Detect Python Base64 One-Liners - Linux
    description: Detects Python one-liners that use base64 decoding on Linux systems.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1027.010
      - T1059.006
    data_sources:
      - process_creation
      - linux
  - title: Detect Python Base32 One-Liners - Linux
    description: Detects Python one-liners that use base32 decoding on Linux systems.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1027.010
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Attackers are increasingly leveraging Python one-liners with base64 encoding on Linux systems to deliver and execute malicious payloads. This technique allows for effective obfuscation, making it harder for conventional security solutions to detect the true nature of the executed commands. The use of `base64` within Python scripts executed directly from the command line is a red flag, as it is rarely observed in standard administrative tasks but is frequently used to hide malicious intent. Defenders must prioritize detecting this behavior to uncover potentially compromised systems and prevent further escalation. This activity has been observed in conjunction with fake AI websites used to deliver malware.

## Attack Chain

1.  An attacker gains initial access to a Linux system through an undisclosed method (e.g., exploiting a vulnerability or social engineering).
2.  The attacker uploads or creates a script containing a base64-encoded payload.
3.  The attacker uses a Python one-liner, invoking the `python` interpreter.
4.  The Python script imports the `base64` module.
5.  The script decodes the base64-encoded payload using functions like `b64decode`, `b32decode`, or similar.
6.  The decoded payload is executed using `eval()` or `exec()` within the same Python one-liner.
7.  The executed payload establishes persistence, downloads further malware, or performs lateral movement.
8.  The attacker achieves their objective, such as data exfiltration or system compromise.

## Impact

Successful exploitation can lead to a full system compromise, data exfiltration, or the deployment of persistent backdoors. The obfuscation techniques make detection difficult, potentially allowing attackers to operate undetected for extended periods. While the specific number of victims and targeted sectors remain unknown, the technique's effectiveness in evading security measures makes it a high-priority threat.

## Recommendation

*   Deploy the Sigma rule "Detect Python Base64 One-Liners - Linux" to your SIEM to detect the execution of Python one-liners utilizing base64 decoding (logsource: process_creation/linux).
*   Investigate any process creation events matching the Sigma rule, focusing on the parent processes and executed commands to identify the source of the malicious activity.
*   Enable and monitor process creation logs on Linux systems to ensure visibility of command-line execution, which is essential for detecting this type of attack (logsource: process_creation/linux).
*   Implement application control policies to restrict the execution of unsigned or untrusted scripts, mitigating the risk of malicious payload execution after decoding.
