---
title: Linux Shared Object Load via LoLBin
slug: 2026-07-shared-object-lolbin
description: Adversaries can leverage Living Off The Land Binaries (LoLBins) such as `openssl`, `python`, or `ruby` to load malicious shared object files (`.so`) into memory on Linux systems, aiming to evade detection by disguising the payload as legitimate process activity; detection engineers must investigate the full command line, parent process chain, executing user, and the reputation/location of the referenced shared object file to differentiate malicious activity from legitimate development or administration tasks.
date: "2026-07-06T14:26:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - defense-evasion
  - execution
  - endpoint
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This rule detects when a process not commonly used to load shared objects, is executed with arguments that load a shared object file. This technique can load a malicious shared object into memory while attempting to evade detection.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: An attacker can launch openssl -engine /tmp/libcrypto.so or a short python -c snippet that calls cdll.LoadLibrary('/tmp/libx.so') to execute a rogue library while blending in with legitimate system activity.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can launch openssl -engine /tmp/libcrypto.so or a short python -c snippet that calls cdll.LoadLibrary('/tmp/libx.so') to execute a rogue library while blending in with legitimate system activity.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_lolbin_so_load.toml
  - https://gtfobins.github.io/#+library%20load
rules:
  - title: Linux Shared Object Load via LoLBin
    description: Detects suspicious loading of shared object files (.so) by Living Off The Land Binaries (LoLBins) such as openssl, python, ruby, or various shell interpreters, indicating potential defense evasion and code execution on Linux systems.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1218
      - T1574
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Adversaries are known to employ Living Off The Land Binaries (LoLBins) to execute malicious code while attempting to blend in with legitimate system activities on Linux environments. This technique involves using trusted system utilities like `openssl`, `python`, or `ruby`, or even common shell interpreters, to load arbitrary shared object (`.so`) files into memory. For instance, an attacker might use `openssl -engine /tmp/libmalware.so` or `python -c 'import ctypes; ctypes.CDLL("/tmp/libx.so")'` to load and execute a malicious library. This method allows adversaries to achieve code execution or defense evasion by proxying through legitimate processes, making it harder for security tools to distinguish malicious behavior from normal administrative or development tasks. This rule, updated on July 6, 2026, aims to detect such activity, which typically indicates a post-compromise phase where an attacker is establishing persistence, escalating privileges, or performing other malicious actions.

## Attack Chain

1.  **Initial Access:** An adversary gains initial access to a Linux host, typically through means such as exploiting a vulnerable service, using compromised credentials, or executing a malicious payload delivered via phishing.
2.  **Staging Malicious Library:** Following initial access, the adversary stages a malicious shared object library (e.g., `libevil.so`) to a writable location on the compromised system, often a temporary directory like `/tmp` or a user's home directory.
3.  **Executing LoLBin:** The adversary executes a Living Off The Land Binary (LoLBin) or a shell interpreter (e.g., `openssl`, `python`, `ruby`, `bash`, `vim`) with specific command-line arguments designed to load the staged malicious shared object.
4.  **Malicious Code Execution:** The executed LoLBin loads the malicious shared object, which then executes its embedded code within the context of the legitimate process, leveraging functions like `ctypes.CDLL()` in Python or `Fiddle.dlopen()` in Ruby.
5.  **Post-Exploitation Activity:** The malicious code performs follow-on actions, which may include establishing persistence (e.g., modifying `/etc/ld.so.preload`, cron jobs, systemd services), escalating privileges to gain higher access, or collecting system and user credentials.
6.  **Command and Control:** The loaded malicious library might initiate covert outbound network connections to a command and control (C2) server to receive further instructions or transmit collected data.
7.  **Data Exfiltration:** Sensitive information, credentials, or other valuable data collected during the post-exploitation phase are exfiltrated from the compromised host to attacker-controlled infrastructure.
8.  **Defense Evasion:** By leveraging legitimate system binaries to load the malicious payload, the adversary successfully evades detection mechanisms that might otherwise flag unknown or suspicious executables, blending into normal system operations.

## Impact

If this attack succeeds, the Linux host is fully compromised, leading to unauthorized code execution, potential privilege escalation, establishment of persistence, and exfiltration of sensitive data. Adversaries can leverage the compromised system as a beachhead for further network penetration, intellectual property theft, or deployment of ransomware. The impact is significant for any organization utilizing Linux systems for critical infrastructure, data storage, or application hosting, potentially leading to operational disruption, data breaches, and severe reputational damage. The technique itself serves as a defense evasion tactic, making it harder to detect and respond to the initial compromise.

## Recommendation

*   Deploy the Sigma rule "Linux Shared Object Load via LoLBin" provided in this brief to your SIEM and tune it for your environment.
*   Ensure `process_creation` logging is enabled on all Linux endpoints to capture command-line arguments and parent-child process relationships, which are critical for activating the provided Sigma rule.
*   Monitor for any `openssl`, `python`, `ruby`, or shell (`bash`, `sh`, `zsh`, etc.) processes loading shared object files (`.so`) from temporary (`/tmp`, `/dev/shm`) or user-writable directories.
*   Restrict plugin and engine loads to approved library directories and enforce strict file integrity checks on critical system binaries and libraries to prevent tampering.
*   Review and secure configurations related to `ld.so.preload`, shell startup files, cron jobs, and systemd services to prevent unauthorized persistence mechanisms.
