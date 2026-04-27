---
title: Unpatched GNU Inetutils Telnet Remote Code Execution Vulnerability
slug: 2026-03-gnu-inetutils-telnet-rce
description: A remote code execution vulnerability exists in the GNU Inetutils Telnet server, potentially allowing unauthenticated attackers to execute arbitrary code on vulnerable systems.
date: "2026-03-19T10:18:48Z"
severities:
  - critical
tags:
  - telnet
  - rce
  - inetutils
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rxwlwl/unpatched_gnu_inetutils_telnet_rce/
  - https://lists.gnu.org/archive/html/bug-inetutils/2026-03/msg00031.html
rules:
  - title: Detect Telnet Process Creation
    description: Detects the execution of the telnet command, which may indicate unauthorized access or exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1021.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Telnet Connection on Non-Standard Port
    description: Detects outbound telnet connections on ports other than the default port 23, which could indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A remote code execution vulnerability has been reported in the GNU Inetutils Telnet server. The vulnerability remains unpatched, posing a significant risk to systems running vulnerable versions of the software. While specific details about the vulnerability are scarce, its presence allows unauthenticated attackers to potentially execute arbitrary code on affected systems. Defenders should treat any instance of Inetutils Telnet as potentially compromised and take steps to mitigate the risk. The…
