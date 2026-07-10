---
title: Python Site or User Customize File Creation for Persistence
slug: 2024-01-python-startup-hook-persistence
description: Attackers can exploit Python's sitecustomize.py and usercustomize.py files for persistence by injecting malicious code, allowing them to execute arbitrary commands upon Python startup.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - python
  - startup-hook
  - linux
vendors:
  - Python
products:
  - Python
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_site_and_user_customize_file_creation.toml
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/018/
  - https://attack.mitre.org/techniques/T1574/
rules:
  - title: Linux Python Startup Hook File Creation
    description: Detects the creation of sitecustomize.py or usercustomize.py in standard Python directories, indicating a potential persistence attempt.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - file_event
      - linux
  - title: Suspicious Process Executing Python with Modified Startup Hooks
    description: Detects when a process executes Python after modification of startup hook files
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This brief covers the exploitation of Python startup hooks for persistence on Linux systems. Attackers can modify or create `sitecustomize.py` and `usercustomize.py` files, which Python automatically executes on startup, allowing for arbitrary code execution. This technique is valuable for adversaries seeking to maintain covert access and execute commands without relying on traditional persistence mechanisms. The Elastic detection rule focuses on identifying unauthorized creation or modification of these files in system-wide, user-specific, and virtual environment locations, while excluding known benign processes like package managers and system update tools. Detecting these malicious modifications is crucial for defenders to identify and prevent unauthorized persistence mechanisms.

## Attack Chain

1.  Attacker gains initial access to a Linux system through vulnerabilities, compromised credentials, or other methods.
2.  The attacker identifies locations where Python's `sitecustomize.py` or `usercustomize.py` files are loaded. These locations include system-wide directories (`/usr/lib/python*/sitecustomize.py`) and user-specific configurations (`/home/*/.config/python/usercustomize.py`).
3.  The attacker creates or modifies the target `sitecustomize.py` or `usercustomize.py` file with malicious Python code. The injected code could download and execute a payload, establish a reverse shell, or perform other malicious activities.
4.  The attacker ensures the modified files are in the correct locations with the appropriate permissions.
5.  When a user or system process executes Python, the malicious code within `sitecustomize.py` or `usercustomize.py` is automatically executed.
6.  The injected code establishes a persistent connection to a command-and-control (C2) server, allowing the attacker to remotely control the compromised system.
7.  The attacker uses the established connection to perform further reconnaissance, lateral movement, or data exfiltration.

## Impact

Successful exploitation allows attackers to establish persistent access to compromised systems. By hijacking Python startup, attackers can execute arbitrary code each time Python is run, potentially leading to data theft, system compromise, or further propagation of malware. While the source does not specify a precise number of victims, the widespread use of Python makes this technique applicable across various sectors, including software development, data science, and system administration. If successful, attackers can maintain a long-term presence on the affected systems, posing a significant threat to data confidentiality and system integrity.

## Recommendation

*   Deploy the Sigma rule "Linux Python Startup Hook File Creation" to your SIEM and tune for your environment to detect malicious file creation events in Python's site-package directories.
*   Monitor process creation events for Python interpreters executing with modified `sitecustomize.py` or `usercustomize.py` files (process_creation log source).
*   Regularly audit the contents of `sitecustomize.py` and `usercustomize.py` files on critical systems to identify unauthorized modifications.
*   Enable Elastic Defend to collect file creation events and process metadata as required by the provided detection rules.
*   Update the exclusion list in the provided Sigma rule to include any legitimate processes in your environment that modify `sitecustomize.py` or `usercustomize.py`.
