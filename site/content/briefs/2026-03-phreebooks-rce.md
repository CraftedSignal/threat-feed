---
title: PhreeBooks ERP 5.2.3 Remote Code Execution Vulnerability
slug: 2026-03-phreebooks-rce
description: PhreeBooks ERP 5.2.3 is vulnerable to remote code execution, allowing authenticated attackers to upload and execute arbitrary PHP files via the image manager, leading to reverse shell connections and system command execution.
date: "2026-03-24T12:16:07Z"
severities:
  - critical
tags:
  - rce
  - vulnerability
  - php
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25647
  - https://www.exploit-db.com/exploits/46645
rules:
  - title: Detect Suspicious PHP Upload via Image Manager
    description: Detects attempts to upload PHP files through the image manager by monitoring POST requests with PHP content.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect PHP execution from unusual web paths
    description: Detects PHP execution from unusual web paths, indicating potential RCE exploitation
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PhreeBooks ERP version 5.2.3 is susceptible to a remote code execution (RCE) vulnerability (CVE-2019-25647) within its image manager component. This flaw enables authenticated attackers to bypass file extension restrictions and upload malicious PHP files. Successful exploitation allows attackers to execute arbitrary code on the underlying server, potentially leading to complete system compromise. The vulnerability exists because the image manager lacks adequate validation of uploaded file…
