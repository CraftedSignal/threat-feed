---
title: Systeminformation Library Vulnerable to Command Injection via NetworkManager Profile Name
slug: 2026-05-systeminformation-nm-injection
description: The systeminformation library is vulnerable to command injection on Linux systems due to unsanitized NetworkManager connection profile names, allowing attackers to execute arbitrary shell commands via a crafted profile when `networkInterfaces()` is called.
date: "2026-05-13T15:30:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - linux
  - networkmanager
products:
  - networkmanager
  - nmcli
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-hvx9-hwr7-wjj9
rules:
  - title: Detect NetworkManager Profile Creation with Shell Metacharacters
    description: Detects the creation of NetworkManager connection profiles with shell metacharacters in their names, potentially indicating a command injection attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1059.004
      - T1546.004
    data_sources:
      - process_creation
      - linux
  - title: Detect systeminformation NetworkManager Command Injection
    description: Detects command injection attempts via NetworkManager connection names when systeminformation library is in use.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `systeminformation` library is vulnerable to a command injection flaw affecting Linux systems. The vulnerability exists within the `networkInterfaces()` function, specifically when handling active NetworkManager connection profile names. If a NetworkManager connection profile name contains shell metacharacters, the library fails to sanitize the input before using it in shell commands. This allows an attacker who can create or rename an active NetworkManager connection profile to inject and execute arbitrary shell commands with the privileges of the Node.js process using the `systeminformation` library. This vulnerability was validated against real NetworkManager and nmcli. Successful exploitation allows for local privilege escalation if the Node.js process is running with elevated privileges.

## Attack Chain

1.  Attacker creates or modifies a NetworkManager connection profile with a malicious name containing shell metacharacters (e.g., `name$(...)`, `name"; ...; #`).
2.  The crafted NetworkManager profile is activated via `nmcli connection up <malicious_profile_name>`.
3.  A Node.js application uses the `systeminformation` library and calls the `networkInterfaces()` function.
4.  `networkInterfaces()` executes `nmcli device status` to retrieve network interface information, including the connection name.
5.  The library parses the `connectionName` from the output of `nmcli device status` without proper sanitization.
6.  The unsanitized `connectionName` is interpolated into shell commands executed via `execSync()` in `getLinuxIfaceDHCPstatus()`, `getLinuxIfaceDNSsuffix()`, and `getLinuxIfaceIEEE8021xAuth()`.
7.  The injected shell commands are executed with the privileges of the Node.js process.
8.  The attacker achieves arbitrary command execution on the system.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the target system with the privileges of the Node.js process using the `systeminformation` library. This could lead to local privilege escalation if the Node.js process is running with elevated privileges. Affected deployments include local inventory agents, monitoring agents, diagnostics tools, admin dashboard backends collecting host information, and privileged local desktop or device-management agents. If such a process runs with elevated privileges, the injected command executes with those same elevated privileges.

## Recommendation

*   Implement input sanitization or, preferably, avoid shell interpolation entirely by using `execFileSync()` or `spawnSync()` with argument arrays as recommended in the advisory. This mitigates the command injection vulnerability in `lib/network.js` (specifically lines 620, 660, and 676).
*   Monitor for suspicious NetworkManager connection profile modifications, specifically looking for profile names containing shell metacharacters as part of a broader strategy to detect command injection attempts.
*   Deploy the provided Sigma rules to detect exploitation attempts by monitoring for `nmcli` commands with connection names containing shell metacharacters in process execution logs.
*   Audit Node.js applications using `systeminformation` on Linux systems and prioritize patching or implementing the suggested mitigations.
