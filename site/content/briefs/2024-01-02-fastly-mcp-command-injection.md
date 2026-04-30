---
title: FastlyMCP Command Injection Vulnerability (CVE-2026-7220)
slug: 2024-01-02-fastly-mcp-command-injection
description: A command injection vulnerability (CVE-2026-7220) exists in jackwrichards FastlyMCP allowing remote attackers to execute arbitrary OS commands by manipulating the command argument in the fastly-mcp.mjs file.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - cve-2026-7220
  - fastly-mcp
products:
  - FastlyMCP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7220
    cvss: 7.3
    epss: 0.01039
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7220
rules:
  - title: Detect FastlyMCP Command Injection Attempt
    description: Detects attempts to exploit the FastlyMCP command injection vulnerability by monitoring for suspicious parameters in web server logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Process Execution via FastlyMCP
    description: Detects suspicious processes spawned by the FastlyMCP application, indicating potential command injection exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-7220, has been discovered in jackwrichards FastlyMCP up to commit 6f3d0b0e654fc51076badc7fa16c03c461f95620. The vulnerability resides within the `fastly-mcp.mjs` file of the `fastly_cli Tool` component. Successful exploitation allows a remote attacker to inject and execute arbitrary operating system commands by manipulating the `command` argument. The exploit is publicly known and actively usable. Given FastlyMCP's rolling release model, specific affected versions are unavailable, increasing the difficulty of patching. This vulnerability poses a significant risk as it can lead to complete system compromise.

## Attack Chain

1. An attacker identifies a vulnerable instance of FastlyMCP running a version up to commit 6f3d0b0e654fc51076badc7fa16c03c461f95620.
2. The attacker crafts a malicious HTTP request targeting the `fastly-mcp.mjs` file.
3. The malicious request includes a manipulated `command` argument containing OS command injection payloads.
4. The FastlyMCP application processes the request, passing the attacker-controlled `command` argument to an underlying OS command execution function without proper sanitization.
5. The injected OS command is executed by the server with the privileges of the FastlyMCP application.
6. The attacker gains arbitrary code execution on the server, enabling further malicious activities.
7. The attacker may then establish persistence via web shells or by modifying system configurations.
8. Ultimately, the attacker achieves complete control over the system, potentially leading to data theft, service disruption, or further lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-7220 allows attackers to execute arbitrary OS commands on the affected system. This can lead to full system compromise, potentially resulting in data breaches, service disruption, and lateral movement to other systems within the network. The lack of specific versioning information due to the rolling release model makes identifying and patching vulnerable instances challenging, potentially increasing the number of victims.

## Recommendation

*   Monitor web server logs for suspicious requests targeting `fastly-mcp.mjs` with unusual parameters in the query string to detect potential exploitation attempts (see the Sigma rule `Detect FastlyMCP Command Injection Attempt`).
*   Implement input validation and sanitization for the `command` argument in `fastly-mcp.mjs` to prevent command injection, though patching is preferable.
*   Deploy the Sigma rule `Detect Suspicious Process Execution via FastlyMCP` to identify potential malicious process execution originating from FastlyMCP.
