---
title: Admin Express 1.2.5.485 Local SEH Buffer Overflow Vulnerability
slug: 2026-03-admin-express-buffer-overflow
description: Admin Express 1.2.5.485 is susceptible to a local structured exception handling buffer overflow vulnerability, enabling local attackers to execute arbitrary code via a crafted payload in the Folder Path field of the System Compare feature.
date: "2026-03-23T14:00:00Z"
severities:
  - high
tags:
  - cve-2019-25612
  - buffer-overflow
  - local-privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25612
  - https://admin-express.en.softonic.com/
  - https://admin-express.en.softonic.com/download
  - https://www.exploit-db.com/exploits/46805
  - https://www.vulncheck.com/advisories/admin-express-local-seh-buffer-overflow-via-folder-path
rules:
  - title: Detect Suspicious Process Creation from Admin Express
    description: Detects the creation of suspicious processes spawned by Admin Express, which might indicate successful exploitation of CVE-2019-25612.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Admin Express Executing WScript or CScript
    description: Detects the execution of WScript or CScript by Admin Express, often used to execute malicious scripts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Admin Express 1.2.5.485 contains a local structured exception handling (SEH) buffer overflow vulnerability that allows a local attacker to execute arbitrary code with the privileges of the application. This vulnerability, identified as CVE-2019-25612, was reported in March 2026. The attack involves crafting a specific alphanumeric encoded payload and injecting it into the 'Folder Path' field within the Admin Express application. Successful exploitation could lead to complete system compromise…
