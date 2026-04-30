---
title: Gigabyte Control Center Arbitrary File Write Vulnerability
slug: 2026-03-gigabyte-file-write
description: Gigabyte Control Center has an Arbitrary File Write vulnerability (CVE-2026-4415) that allows unauthenticated remote attackers to write arbitrary files to any location on the underlying operating system, leading to arbitrary code execution or privilege escalation.
date: "2026-03-30T08:16:18Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4415
  - arbitrary-file-write
  - privilege-escalation
  - code-execution
  - gigabyte
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4415
  - https://www.twcert.org.tw/en/cp-139-10804-689cd-2.html
  - https://www.twcert.org.tw/tw/cp-132-10803-ae014-1.html
rules:
  - title: Detect Gigabyte Control Center Arbitrary File Creation
    description: Detects suspicious file creation activity by Gigabyte Control Center that may indicate exploitation of CVE-2026-4415.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Gigabyte Control Center Spawning cmd.exe
    description: Detects Gigabyte Control Center spawning cmd.exe, which could indicate command execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Gigabyte Control Center application is vulnerable to an arbitrary file write vulnerability, identified as CVE-2026-4415. The vulnerability exists because when the "pairing" feature is enabled, it allows unauthenticated remote attackers to write arbitrary files to any location on the underlying operating system. This issue was reported on March 30, 2026. Successful exploitation could allow attackers to achieve arbitrary code execution or escalate privileges on the affected system. This poses…
