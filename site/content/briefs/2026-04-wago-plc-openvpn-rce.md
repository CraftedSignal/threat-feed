---
title: WAGO PLC OpenVPN Configuration Vulnerability (CVE-2024-1490)
slug: 2026-04-wago-plc-openvpn-rce
description: An authenticated remote attacker with high privileges can exploit the OpenVPN configuration via the web-based management interface of a WAGO PLC to achieve arbitrary command execution on the device.
date: "2026-04-09T11:16:19Z"
severities:
  - high
tags:
  - cve-2024-1490
  - wago-plc
  - openvpn
  - rce
  - code-injection
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2024-1490
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-1490
  - https://certvde.com/de/advisories/VDE-2024-008
  - https://wago.csaf-tp.certvde.com/.well-known/csaf/white/2026/vde-2024-008.json
ioc_counts:
  url: 2
rules:
  - title: Detect OpenVPN Configuration Changes via Web Interface
    description: Detects POST requests to the WAGO PLC web interface that modify OpenVPN configurations, potentially indicating exploitation of CVE-2024-1490.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect OpenVPN User Script Parameter in Web Logs
    description: Detects the presence of 'user_script=' in web server logs, potentially indicating an attempt to inject malicious scripts into the OpenVPN configuration.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2024-1490 describes a critical vulnerability affecting WAGO Programmable Logic Controllers (PLCs). A remote attacker with existing high-privilege access to the PLC's web-based management interface can exploit the OpenVPN configuration. The vulnerability stems from insufficient input validation within the OpenVPN configuration settings. If the PLC's OpenVPN setup permits user-defined scripts, a malicious actor can inject arbitrary shell commands. Successful exploitation allows the attacker…
