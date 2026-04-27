---
title: Emissary OS Command Injection Vulnerability (CVE-2026-35581)
slug: 2026-04-emissary-command-injection
description: Emissary, a P2P data-driven workflow engine, is vulnerable to OS command injection due to insufficient sanitization of the PLACE_NAME parameter in versions prior to 8.39.0, allowing for arbitrary command execution.
date: "2026-04-07T17:16:33Z"
severities:
  - high
tags:
  - cve
  - command injection
  - emissary
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35581
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35581
  - https://github.com/NationalSecurityAgency/emissary/security/advisories/GHSA-6c37-7w4p-jg9v
rules:
  - title: Detect Suspicious PLACE_NAME Parameter Modification
    description: Detects modifications to the PLACE_NAME parameter in Emissary configuration files that contain shell metacharacters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
  - title: Detect Emissary Command Execution via /bin/sh -c
    description: Detects command execution events originating from the emissary process with /bin/sh -c as a parent.
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

Emissary is a P2P-based data-driven workflow engine. Prior to version 8.39.0, a critical vulnerability, CVE-2026-35581, existed within the Executrix utility class. This class constructs shell commands by concatenating configuration-derived values, specifically the PLACE_NAME parameter, without proper sanitization. The inadequate sanitization process only replaced spaces with underscores, leaving shell metacharacters (;, |, $, `, (, ), etc.) vulnerable to injection. This flaw allows attackers to…
