---
title: Lakeside SysTrack Agent Local Privilege Escalation via Race Condition (CVE-2026-35099)
slug: 2026-04-lakeside-systrack-lpe
description: Lakeside SysTrack Agent 11 before 11.2.1.28 is vulnerable to a race condition that allows for local privilege escalation to SYSTEM, as tracked by CVE-2026-35099.
date: "2026-04-01T16:23:50Z"
severities:
  - high
tags:
  - lakeside
  - systrack
  - privilege-escalation
  - race-condition
  - cve-2026-35099
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35099
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35099
  - https://documentation.lakesidesoftware.com/en/Content/Release%20Notes/Agent/11.2.1.28%20Hotfix%20Agent%20Release%20Notes.htm?tocpath=Release%20Notes%7CAgent%7C_____8
rules:
  - title: Detect Suspicious SysTrack Agent Process Creation
    description: Detects potential exploitation of Lakeside SysTrack Agent by monitoring for suspicious process creations initiated by the agent.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Detect SysTrack Agent Writing Executables
    description: Detects the SysTrack Agent writing executable files, potentially indicating a privilege escalation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Lakeside SysTrack Agent, a system monitoring tool, contains a local privilege escalation vulnerability. Specifically, versions of Agent 11 prior to 11.2.1.28 are susceptible to a race condition (CWE-362) that can be exploited by a local attacker to gain SYSTEM privileges. This vulnerability, identified as CVE-2026-35099, allows an attacker with limited privileges to execute arbitrary code with the highest level of permissions on the system. Successful exploitation could lead to complete system…
