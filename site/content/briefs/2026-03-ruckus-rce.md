---
title: Ruckus Unleashed Authenticated Remote Code Execution via CVE-2023-7338
slug: 2026-03-ruckus-rce
description: CVE-2023-7338 is a remote code execution vulnerability affecting Ruckus Unleashed when gateway mode is enabled, allowing authenticated remote attackers to execute arbitrary code by sending specially crafted requests through the web-based management interface.
date: "2026-03-26T20:16:08Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2023-7338
  - ruckus
  - rce
  - os command injection
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-7338
  - https://support.ruckuswireless.com/security_bulletins/320
  - https://www.vulncheck.com/advisories/ruckus-unleashed-authenticated-rce-in-gateway-mode
rules:
  - title: Detect Suspicious Ruckus Unleashed HTTP Requests
    description: Detects suspicious HTTP requests to Ruckus Unleashed web interface indicative of potential exploitation attempts of CVE-2023-7338
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect Ruckus Unleashed OS Command Injection via CVE-2023-7338
    description: Detects possible OS command injection attempts against Ruckus Unleashed web interface.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2023-7338 is a critical remote code execution (RCE) vulnerability found in Ruckus Unleashed, a Wi-Fi network management solution. The vulnerability resides within the web-based management interface and requires the affected system to be operating in gateway mode. An authenticated attacker can exploit this flaw by crafting and sending malicious requests to the management interface, resulting in arbitrary code execution on the device. This vulnerability was reported by VulnCheck and assigned…
