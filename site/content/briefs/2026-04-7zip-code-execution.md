---
title: 7-Zip Multiple Vulnerabilities Allow Remote Code Execution
slug: 2026-04-7zip-code-execution
description: Multiple vulnerabilities in 7-Zip allow an attacker to execute arbitrary program code with the privileges of the service, potentially leading to system compromise.
date: "2026-04-01T09:23:57Z"
severities:
  - high
tags:
  - 7-zip
  - code-execution
  - vulnerability
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2261
rules:
  - title: Detect Suspicious 7-Zip Process Execution
    description: Detects suspicious processes spawned by 7-Zip, which could indicate exploitation of a vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect 7-Zip executing from unusual directory
    description: Detects 7-Zip executing from a non-standard directory, possibly indicating a malicious copy.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified in 7-Zip, a widely used file archiver. An attacker who successfully exploits these vulnerabilities could execute arbitrary program code with the privileges of the 7-Zip service. This could allow an attacker to gain elevated privileges on the system, potentially leading to complete system compromise. The vulnerabilities are present in the Windows version of 7-Zip. This issue impacts systems where 7-Zip is installed and used, especially in…
