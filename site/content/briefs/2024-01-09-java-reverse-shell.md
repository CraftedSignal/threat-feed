---
title: Potential Reverse Shell via Java on Linux
slug: 2024-01-09-java-reverse-shell
description: The execution of a Linux shell process from a Java JAR application following an incoming network connection may indicate reverse shell activity.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reverse-shell
  - java
  - linux
  - execution
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_shell_via_java_revshell_linux.toml
rules:
  - title: Potential Reverse Shell via Java
    description: Detects the execution of a Linux shell process from a Java JAR application after an incoming network connection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Java Process with Network Connection followed by Shell Execution
    description: Detects a Java process initiating a network connection followed by the execution of a shell.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
      - T1071
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies the execution of a Linux shell process initiated by a Java application after an incoming network connection, a behavior indicative of a potential reverse shell. Attackers can exploit Java applications running on Linux systems to establish reverse shells, enabling remote control over compromised systems. This technique involves executing shell commands via Java processes following a network connection. The rule specifically monitors for shell executions spawned by Java processes post-network connection, excluding legitimate processes to minimize false positives. This ensures that only suspicious Java activity is flagged, potentially revealing reverse shell attempts. The original rule was created on 2023-07-04 and updated on 2026-05-05.

## Attack Chain

1. A Java application (e.g., /usr/bin/java) establishes a network connection, either accepting an incoming connection or attempting an outbound connection.
2. The Java process executes a shell command using a command interpreter.
3. A shell process (bash, sh, zsh, etc.) is spawned as a child process of the Java application.
4. The shell process executes commands based on the attacker's input, potentially downloading or executing malicious payloads.
5. The attacker gains remote access and control over the compromised system.
6. The attacker may perform internal reconnaissance to gather information about the environment.
7. The attacker could escalate privileges to gain higher-level access within the system.
8. The attacker may attempt lateral movement to other systems within the network.

## Impact

A successful reverse shell allows an attacker to gain complete control over the compromised Linux system. This can lead to data exfiltration, installation of malware, or further exploitation of the network. The impact ranges from system compromise to potential data breaches. Detecting and preventing reverse shells is crucial to maintain the integrity and security of Linux environments.

## Recommendation

*   Deploy the Sigma rule `Potential Reverse Shell via Java` to your SIEM and tune for your environment.
*   Enable Elastic Defend integration to collect the necessary network and process execution data.
*   Review network connection details, focusing on destination IP addresses, as highlighted in the rule description, to identify potentially malicious external connections.
*   Investigate Java processes initiating network connections, examining executable paths and arguments, as described in the rule's investigation steps, to detect unauthorized JAR files.
*   Update and patch Java environments to mitigate known vulnerabilities that could be exploited to establish reverse shells.
