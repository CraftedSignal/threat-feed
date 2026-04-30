---
title: DVDXPlayer Pro 5.5 Local Buffer Overflow Vulnerability (CVE-2019-25604)
slug: 2026-03-dvdxplayer-bof
description: DVDXPlayer Pro 5.5 is vulnerable to a local buffer overflow, allowing local attackers to execute arbitrary code by crafting malicious playlist files.
date: "2026-03-23T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - buffer-overflow
  - seh-overwrite
  - cve-2019-25604
  - dvdxplayer
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25604
  - https://www.exploit-db.com/exploits/46962
  - https://www.vulncheck.com/advisories/dvdxplayer-pro-local-buffer-overflow-with-seh
rules:
  - title: DVDXPlayer Pro Spawning Suspicious Processes
    description: Detects DVDXPlayer Pro spawning potentially malicious child processes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: DVDXPlayer Pro SEH Overwrite Attempt
    description: Detects potential Structured Exception Handler (SEH) overwrite attempts by monitoring for specific memory access patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

DVDXPlayer Pro 5.5 is susceptible to a local buffer overflow vulnerability (CVE-2019-25604) that can be exploited by local attackers. This vulnerability allows for arbitrary code execution through the creation of specially crafted playlist files (.plf). The attack involves overflowing a buffer and hijacking the Structured Exception Handling (SEH) chain to execute attacker-controlled code within the context of the application. The vulnerability was reported in March 2026. Successful exploitation…
