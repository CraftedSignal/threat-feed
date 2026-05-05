---
title: A-G-U-P-T-A wireshark-mcp OS Command Injection Vulnerability
slug: 2024-01-wireshark-mcp-command-injection
description: A-G-U-P-T-A wireshark-mcp is vulnerable to remote OS command injection (CVE-2026-7785) via manipulation of the `quick_capture` function in `pyshark_mcp.py`, potentially allowing attackers to execute arbitrary commands on the system.
date: "2026-05-05T00:16:17Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - command-injection
  - web-application
  - rolling-release
vendors:
  - A-G-U-P-T-A
products:
  - wireshark-mcp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7785
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7785
rules:
  - title: Detect wireshark-mcp Command Injection Attempt via HTTP Request
    description: Detects potential command injection attempts targeting the quick_capture function in wireshark-mcp based on suspicious keywords in the request URI.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Process Execution from wireshark-mcp
    description: Detects unexpected process executions originating from the wireshark-mcp application, indicating potential command injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A remote OS command injection vulnerability (CVE-2026-7785) has been identified in the `quick_capture` function of the `pyshark_mcp.py` file within the A-G-U-P-T-A `wireshark-mcp` project. The vulnerability allows for the injection and execution of arbitrary OS commands via crafted inputs. The project operates on a rolling release basis, lacking specific version numbers, which hinders targeted patching. Publicly available exploits increase the risk of active exploitation against vulnerable deployments. The vendor was notified via issue report but has yet to respond as of the time of this report.

## Attack Chain

1.  An attacker identifies a vulnerable instance of A-G-U-P-T-A `wireshark-mcp`.
2.  The attacker crafts a malicious request targeting the `quick_capture` function within the `pyshark_mcp.py` file.
3.  The crafted request includes an OS command injection payload within the parameters of the `quick_capture` function.
4.  The `wireshark-mcp` application processes the malicious request without proper sanitization or input validation.
5.  The injected OS command is executed by the system with the privileges of the `wireshark-mcp` application.
6.  The attacker gains the ability to perform actions such as reading sensitive files, modifying system configurations, or establishing a reverse shell.
7.  The attacker pivots within the network, leveraging the compromised system to target other internal resources.

## Impact

Successful exploitation of CVE-2026-7785 can lead to complete system compromise, data breaches, and lateral movement within the affected network. The absence of versioning due to the rolling release nature of `wireshark-mcp` increases the difficulty of identifying and patching vulnerable instances. Given the availability of public exploits, organizations running this software are at significant risk.

## Recommendation

*   Inspect network traffic for suspicious POST requests containing shell commands targeting the `quick_capture` function in `pyshark_mcp.py` using the provided Sigma rule.
*   Monitor process creation events for unexpected processes spawned by the `wireshark-mcp` application, based on the provided Sigma rule.
*   Block network connections originating from systems where exploitation is suspected, based on the IOC `edaf604416fbc94a201b4043092d4a1b09a12275`.
*   Implement robust input validation and sanitization mechanisms within the `wireshark-mcp` application to prevent command injection attacks.
