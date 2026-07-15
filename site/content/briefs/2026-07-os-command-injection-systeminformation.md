---
title: OS Command Injection Vulnerability in systeminformation Library via networkInterfaces()
slug: 2026-07-os-command-injection-systeminformation
description: A high-severity OS command injection vulnerability, CVE-2026-50289, exists in the `systeminformation` Node.js library on Linux systems, allowing an attacker who can manipulate `interfaces(5)` configuration files to execute arbitrary commands with the privileges of the calling Node.js process by injecting shell metacharacters into `source` directive paths, which are then unsafely interpolated into an `execSync()` command within the `networkInterfaces()` function.
date: "2026-07-15T23:12:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - os-command-injection
  - systeminformation
  - nodejs
  - linux
  - exploitation
vendors:
  - systeminformation
products:
  - systeminformation (<= 5.31.6)
affected_os:
  - Debian
  - Ubuntu
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A `source` line whose path contains shell metacharacters executes arbitrary commands with the privileges of the calling Node.js process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-5xpp-75jx-m839
iocs:
  - type: payload
    value: /dev/null;id>${marker};echo
ioc_counts:
  payload: 1
rules:
  - title: Detect CVE-2026-50289 Exploitation - Suspicious Shell Execution
    description: Detects CVE-2026-50289 exploitation - processes spawned by Node.js that contain shell metacharacters, indicating OS command injection via `systeminformation` library's `networkInterfaces()` function on Linux.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

The `systeminformation` Node.js library, specifically versions up to and including 5.31.6, is affected by CVE-2026-50289, a high-severity OS command injection vulnerability on Linux systems, particularly Debian/Ubuntu variants utilizing `interfaces(5)`. The `networkInterfaces()` function insecurely handles paths specified in `source` directives within `/etc/network/interfaces` and transitively sourced files. When processing these configuration files to collect DHCP state, the library extracts paths from `source` lines and interpolates them, unquoted, into a shell command string executed via `execSync()`. This allows an attacker capable of placing or influencing a malicious `source` path to inject shell metacharacters, leading to arbitrary command execution. This vulnerability presents a significant risk to applications using `systeminformation` as local inventory, monitoring, or admin-dashboard backends, as successful exploitation grants the attacker command execution with the privileges of the Node.js process.

## Attack Chain

1. An attacker gains the ability to write to or influence the content of `/etc/network/interfaces` or any file transitively `source`d by it. This could be a lower-privileged process, a configuration management hook, or a tool that materializes interface snippets from semi-trusted input.
2. The attacker inserts a `source` directive into one of these configuration files, where the path contains shell metacharacters (e.g., `/dev/null;id>${marker};echo`).
3. A Node.js application, running on the vulnerable Linux system, invokes the `systeminformation` library's `networkInterfaces()` function (or `getStaticData()`, `getAllData()`).
4. The `networkInterfaces()` function on Linux calls `getLinuxDHCPNics()`, which in turn calls `checkLinuxDCHPInterfaces('/etc/network/interfaces')`.
5. Inside `checkLinuxDCHPInterfaces()`, the function reads the content of the `interfaces` file using `cat ${file} ...`. The `source` directive's malicious path is read and passed as the `file` argument for a recursive call to `checkLinuxDCHPInterfaces()`.
6. In the recursive call, the new malicious `file` path is unquotedly interpolated into another `cat ${file} 2> /dev/null | grep 'iface\\|source'` shell command.
7. The injected shell metacharacters (`/dev/null;id>${marker};echo` for example) break out of the intended `cat` command, leading to the execution of arbitrary commands (e.g., `id`) with the privileges of the Node.js process.
8. The attacker achieves command execution, potentially elevating privileges or performing further malicious actions.

## Impact

Successful exploitation of CVE-2026-50289 leads to arbitrary command execution on the affected Linux system. Any process that calls `networkInterfaces()`, often found in local inventory agents, monitoring and diagnostics agents, admin-dashboard backends, or device-management software, is vulnerable. If these Node.js processes run with elevated privileges (e.g., as root), the injected commands will also execute with those elevated privileges, potentially leading to full system compromise. The vulnerability is easily triggered through ordinary usage of core `systeminformation` APIs, making it a critical risk for systems running vulnerable versions. The attacker gains the ability to run any command, potentially installing backdoors, exfiltrating data, or disrupting services.

## Recommendation

* **Patch CVE-2026-50289 immediately**: Update `systeminformation` to a version greater than 5.31.6 to remediate CVE-2026-50289.
* **Monitor for suspicious `sh` or `bash` process creations**: Deploy the `Detect CVE-2026-50289 Exploitation - Suspicious Shell Execution` Sigma rule to your SIEM.
* **Enable process creation logging**: Ensure `process_creation` logging (e.g., Sysmon on Linux, Auditd) is enabled for Linux systems to capture shell command executions and their arguments.
* **Restrict write access to network configuration files**: Limit write permissions to `/etc/network/interfaces` and related directories (`/etc/network/interfaces.d/`) to only authorized administrators or processes to prevent attackers from injecting malicious `source` directives.
