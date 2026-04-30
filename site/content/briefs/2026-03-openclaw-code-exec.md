---
title: OpenClaw Code Execution via Script Modification (CVE-2026-32979)
slug: 2026-03-openclaw-code-exec
description: OpenClaw before 2026.3.11 is vulnerable to an approval integrity issue (CVE-2026-32979) allowing attackers to execute arbitrary code by modifying approved local scripts before they are executed.
date: "2026-03-29T13:17:02Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-32979
  - code-execution
  - openclaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32979
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-xf99-j42q-5w5p
  - https://www.vulncheck.com/advisories/openclaw-unbound-interpreter-and-runtime-commands-bypass-in-node-host-approval
rules:
  - title: OpenClaw Script Modification Detection
    description: Detects the creation of new files in the OpenClaw scripts directory, indicating potential script modification.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - file_event
      - windows
  - title: OpenClaw Runtime User Process Spawning
    description: Detects processes spawned by the OpenClaw runtime user that are not typical OpenClaw processes.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw, a software application, is susceptible to an approval integrity vulnerability identified as CVE-2026-32979. This flaw exists in versions prior to 2026.3.11. An attacker can exploit this vulnerability to execute malicious code within the context of the OpenClaw runtime user. The attack involves modifying approved local scripts between the time they are approved and the time they are executed. This is possible because exact file binding does not occur, which allows for the alteration of…
