---
title: Detection of Python One-Liners with Base64 Decoding
slug: 2024-01-python-base64-decode
description: This brief outlines a method to detect malicious use of Python one-liners employing base64 decoding to execute obfuscated payloads, a common tactic for evading traditional security measures.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - attack.execution
  - attack.defense-evasion
  - attack.t1059.006
  - attack.t1027.010
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://docs.python.org/3/library/base64.html
  - https://www.virustotal.com/gui/file/bc43e925d7b4b74319f6e74e836a96f1997ba404e14ac566cf12a21e9da463db/behavior
  - https://cloud.google.com/blog/topics/threat-intelligence/cybercriminals-weaponize-fake-ai-websites
rules:
  - title: Detect Python Base64 Encoded Command Execution
    description: Detects Python one-liners using base64 decoding functions in command line executions, indicative of obfuscated payload execution.
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
      - windows
  - title: Detect Alternate Python Base64 Decode Methods
    description: Detects Python one-liners using alternate base64 decoding functions in command line executions.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1027.010
      - T1059.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently leverage Python one-liners with base64 encoding to obfuscate and execute malicious code. This technique bypasses standard security measures by concealing the true nature of the payload. The abuse involves embedding base64-encoded commands within Python scripts, which are then decoded and executed at runtime. While legitimate uses of Python and base64 exist, their combination in a single command line, especially with execution flags, is a strong indicator of malicious activity. This technique has been observed in various attacks, including those originating from fake AI websites, where malicious Python code is injected to perform unauthorized actions. Defenders should monitor for such patterns to identify and neutralize potential threats.

## Attack Chain

1.  Initial Access: The attacker gains access to the system, often through social engineering or exploiting a vulnerability.
2.  Payload Delivery: A base64-encoded payload is delivered to the victim machine via email, website, or other means.
3.  Python Invocation: Python is invoked via the command line, often using `python.exe` or `python3`.
4.  Import Base64 Module: The `import base64` statement is used to load the necessary decoding libraries.
5.  Decoding Execution: The base64-encoded payload is decoded using functions like `base64.b64decode()` within the Python one-liner using the `-c` flag for command execution.
6.  Code Execution: The decoded payload is executed in memory, performing malicious actions such as installing malware or establishing persistence.
7.  Lateral Movement: The attacker leverages the compromised system to move laterally within the network, compromising additional systems.
8.  Data Exfiltration/System Damage: The attacker exfiltrates sensitive data or causes damage to the system, depending on their objectives.

## Impact

Successful exploitation can lead to complete system compromise, data theft, and potentially, a foothold for lateral movement within the network. The use of base64 encoding significantly hinders detection efforts, allowing attackers to operate undetected for extended periods. If successful, organizations could face data breaches, financial losses, and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule targeting `process_creation` events on Windows systems to detect Python commands utilizing base64 decoding functions (`CommandLine|contains` with `import base64`, `b64decode`, and `-c`).
*   Inspect command-line arguments of Python processes for suspicious base64 decoding patterns (as seen in the detection rule).
*   Implement application control policies to restrict the execution of unauthorized Python scripts, mitigating potential exploitation attempts.
*   Enable Sysmon process creation logging to ensure adequate coverage for the provided Sigma rule.
