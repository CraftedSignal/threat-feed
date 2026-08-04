---
title: Remote Code Execution in Flowise via SQLite Configuration Overwrite
slug: 2026-08-flowise-rce
description: Flowise version 3.1.2 is vulnerable to Remote Code Execution (RCE) where an attacker can override the SQLite database path and inject malicious shell commands into the database file structure.
date: "2026-08-04T17:23:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - sqlite
  - injection
  - flowise
  - remote-code-execution
vendors:
  - FlowiseAI
products:
  - Flowise (3.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The injected ' could then be used to wrap the problematic () characters within the cell, which is then closed by the namespace input that also contains a reverse shell payload.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker could abuse this weakness to write an SQLite database to an arbitrary filepath.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-x3hf-7cj6-3r4m
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit Flowise deployments for version 3.1.2 and upgrade
      owner: IT Operations
      due: 24h
      evidence: Source advisory confirms version 3.1.2 as the affected product.
  mitigation_plan:
    - priority: immediate
      action: Run Flowise containers as a non-root user
      owner: IT Operations
      addresses: RCE privilege escalation risk
      evidence: Source notes the Docker image runs as root.
---

Flowise version 3.1.2 contains a critical vulnerability in the "SQLite Record Manager" node that allows for Remote Code Execution. An attacker can leverage the `additionalConfig` input parameter to override the intended SQLite database path, allowing the application to write a database file to arbitrary locations on the filesystem, such as system configuration directories. Because the Flowise Docker image runs with root privileges, this creates an opportunity for privilege escalation or full system compromise.

The vulnerability is exploitable by manipulating the `tableName` and `namespace` inputs to inject shell payloads into the SQLite binary structure. By carefully crafting the table name length, an attacker can manipulate the serial type of the database metadata to wrap malicious commands. If a system process, such as Chromium launched via Puppeteer, reads the resulting malicious SQLite database file (e.g., from an arbitrary path like /etc/chromium/exploit.conf), the injected shell commands are executed, potentially resulting in a reverse shell.

## Attack Chain

1. The attacker configures a malicious SQLite Record Manager node within a Flowise Chatflow.
2. The attacker uses the `additionalConfig` input to set `database` to an arbitrary path, such as `/etc/chromium/exploit.conf`.
3. The attacker sets the `tableName` input to a specific length (e.g., `AAAAAAAAAAAAA`) to force the SQLite serial type to `0x27` (ASCII single quote).
4. The attacker provides a reverse shell payload in the `namespace` field, formatted to close the injection context and execute commands via shell substitution.
5. The attacker triggers an Upsert Vector Store operation, causing Flowise to create the SQLite database file at the attacker-chosen location.
6. The system or application environment launches a process, such as a Chromium browser via Puppeteer, that parses or references the maliciously crafted SQLite file.
7. The process interprets the contents of the database file as commands, leading to the execution of the reverse shell and the establishment of a network connection to the attacker.

## Impact

Successful exploitation allows an unauthenticated or authenticated user to gain arbitrary code execution on the host machine. Given that the default Flowise Docker container runs as root, this provides attackers with full control over the application environment and potentially the host node, enabling data exfiltration or lateral movement within the network.

## Recommendation

* Update Flowise to the latest patched version immediately to remediate the input validation and configuration override vulnerabilities.
* Restrict the ability of the Flowise process to write files to sensitive system directories using container security policies or AppArmor/SELinux profiles.
* Run the Flowise container with a non-root user to mitigate the impact of arbitrary file write and execution vulnerabilities.
* Implement egress filtering to block unexpected outbound network connections from the Flowise environment to unauthorized external IPs.
