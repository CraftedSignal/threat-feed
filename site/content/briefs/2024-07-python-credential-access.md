---
title: First Time Python Accessed Sensitive Credential Files on macOS
slug: 2024-07-python-credential-access
description: This alert triggers on the first instance of a Python process accessing sensitive credential files on macOS, potentially indicating post-exploitation credential theft.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - python
  - macos
  - endpoint
vendors:
  - Python
  - PyTorch
products:
  - Python
  - PyTorch
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/
  - https://github.com/trailofbits/fickling
rules:
  - title: macOS Python Credential File Access
    description: Detects Python processes accessing sensitive credential files on macOS for the first time.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
      - T1555.001
    data_sources:
      - file_event
      - macos
  - title: Suspicious Python Script Execution
    description: Detects suspicious execution of Python scripts, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

This detection rule identifies instances where a Python process accesses sensitive credential files on macOS for the first time. This activity is often indicative of post-exploitation credential theft, where attackers leverage Python code execution (through malicious scripts, compromised dependencies, or model file deserialization) to target sensitive data. Since legitimate Python processes rarely interact with files containing SSH keys, cloud provider credentials, browser session cookies, Kerberos tickets, or keychain databases, such access is considered a high-confidence indicator of compromise. The rule specifically focuses on "first occurrence" events within a 7-day window to minimize noise from legitimate but infrequent access patterns. This alert is designed to detect malicious activity related to Python-based attacks targeting credential stores on macOS systems.

## Attack Chain

1. Initial Access: Attacker gains initial access to the macOS system through a software vulnerability or social engineering.
2. Code Execution: The attacker executes malicious Python code on the compromised system. This could be through a malicious script, a compromised dependency, or exploitation of unsafe deserialization practices like pickle/PyTorch `__reduce__`.
3. Discovery: The Python script enumerates potential credential file locations on the system.
4. Credential Access: The Python script attempts to open and read sensitive files such as SSH keys (`~/.ssh/id_rsa`), AWS credentials (`~/.aws/credentials`), browser cookies, Kerberos tickets (`/tmp/krb5cc_*`), or macOS keychain databases (`~/Library/Keychains/login.keychain-db`).
5. Data Collection: The stolen credentials are saved to a temporary file or memory.
6. Exfiltration: The attacker establishes a network connection to an external server and exfiltrates the collected credential data.
7. Lateral Movement/Privilege Escalation: The attacker uses the stolen credentials to move laterally to other systems or escalate privileges within the network.

## Impact

A successful attack can lead to unauthorized access to sensitive data, lateral movement within the network, and potential privilege escalation. If SSH keys are compromised, attackers can gain access to other systems without authentication. Compromised AWS credentials can lead to unauthorized access to cloud resources, potentially resulting in data breaches and financial losses. Browser cookie theft allows attackers to hijack user sessions, gaining access to web applications and services.

## Recommendation

*   Deploy the Sigma rule `macOS Python Credential File Access` to your SIEM and tune for your environment, ensuring it is enabled and actively monitoring file access events.
*   Enable Elastic Defend endpoint file monitoring to capture `open` events for sensitive credential files, as required by the rule `macOS Python Credential File Access`.
*   Implement `weights_only=True` enforcement for PyTorch model loading to mitigate risks associated with malicious model files, as mentioned in the overview.
*   Investigate and quarantine any Python processes flagged by the Sigma rule `macOS Python Credential File Access` to prevent further data exfiltration or lateral movement.
*   Rotate any compromised credentials (SSH keys, AWS access keys, cloud tokens) identified during incident response, as described in the Triage section.
*   Monitor process command lines for suspicious arguments or script execution related to credential access using the Sigma rule `Suspicious Python Script Execution`.
