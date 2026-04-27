---
title: OpenClaw Remote Code Execution via Node Scope Gate Bypass (CVE-2026-41352)
slug: 2026-04-openclaw-rce
description: OpenClaw before 2026.3.31 is vulnerable to remote code execution (CVE-2026-41352) because a device-paired node can bypass the node scope gate authentication mechanism, allowing attackers with device pairing credentials to execute arbitrary node commands.
date: "2026-04-24T12:00:00Z"
severities:
  - critical
tags:
  - rce
  - vulnerability
  - cve-2026-41352
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-41352
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41352
  - https://github.com/openclaw/openclaw/commit/3886b65ef21d02808c1a106fa1f9f69e22f71c32
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-xj9w-5r6q-x6v4
  - https://www.vulncheck.com/advisories/openclaw-remote-code-execution-via-node-scope-gate-bypass
rules:
  - title: OpenClaw Suspicious Node Command Execution
    description: Detects suspicious command execution originating from OpenClaw processes, potentially indicating exploitation of CVE-2026-41352.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: OpenClaw Network Connection to Uncommon Ports
    description: Detects network connections from OpenClaw to uncommon ports, which may indicate command and control activity after exploiting CVE-2026-41352.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

OpenClaw before version 2026.3.31 suffers from a remote code execution vulnerability (CVE-2026-41352). This flaw exists because a device-paired node can bypass the node scope gate authentication mechanism. An attacker who has already obtained device pairing credentials can exploit this vulnerability to execute arbitrary node commands on the host system. This occurs because the application doesn't perform adequate node pairing validation, allowing malicious actors to potentially gain complete…
