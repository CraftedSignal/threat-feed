---
title: OpenClaw Remote Command Injection via iMessage Attachment Staging (CVE-2026-32917)
slug: 2026-03-openclaw-rce
description: OpenClaw before 2026.3.13 is vulnerable to remote command injection via unsanitized iMessage attachment paths passed to the SCP remote operand, allowing attackers to execute arbitrary commands on configured remote hosts when remote attachment staging is enabled.
date: "2026-03-31T12:16:28Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - command-injection
  - imessage
  - openclaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-32917
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32917
  - https://github.com/openclaw/openclaw/commit/a54bf71b4c0cbe554a84340b773df37ee8e959de
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-g2f6-pwvx-r275
  - https://www.vulncheck.com/advisories/openclaw-remote-command-injection-via-unsanitized-imessage-attachment-paths-in-scp
rules:
  - title: Detect Suspicious Network Activity from OpenClaw
    description: Detects network connections from OpenClaw that may indicate command injection activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - network_connection
      - linux
  - title: Detect Suspicious Process Creation from OpenClaw
    description: Detects creation of shell processes from OpenClaw that may indicate command injection activity.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw, a software application whose specific function is not detailed in the provided context, is vulnerable to a remote command injection flaw. Specifically, versions prior to 2026.3.13 are susceptible. This vulnerability, identified as CVE-2026-32917, resides within the iMessage attachment staging process.  Attackers can exploit this flaw by injecting shell metacharacters into unsanitized remote attachment paths. This occurs because these paths are directly passed to the SCP command…
