---
title: WAGO PLC OpenVPN Configuration Vulnerability (CVE-2024-1490)
slug: 2026-04-wago-plc-openvpn-rce
description: An authenticated remote attacker with high privileges can exploit the OpenVPN configuration via the web-based management interface of a WAGO PLC to achieve arbitrary command execution on the device.
date: "2026-04-09T11:16:19Z"
severities:
  - high
type: advisory
types:
  - advisory
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
iocs:
  - type: url
    value: https://certvde.com/de/advisories/VDE-2024-008
  - type: url
    value: https://wago.csaf-tp.certvde.com/.well-known/csaf/white/2026/vde-2024-008.json
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

CVE-2024-1490 describes a critical vulnerability affecting WAGO Programmable Logic Controllers (PLCs). A remote attacker with existing high-privilege access to the PLC's web-based management interface can exploit the OpenVPN configuration. The vulnerability stems from insufficient input validation within the OpenVPN configuration settings. If the PLC's OpenVPN setup permits user-defined scripts, a malicious actor can inject arbitrary shell commands. Successful exploitation allows the attacker to execute arbitrary code on the underlying operating system of the WAGO PLC, potentially leading to full device compromise. This vulnerability was reported by CERT VDE and impacts WAGO PLCs that utilize a vulnerable web-based management interface and permit user-defined scripts in their OpenVPN configuration.

## Attack Chain

1.  The attacker gains initial high-privilege access to the WAGO PLC's web-based management interface.
2.  The attacker navigates to the OpenVPN configuration section within the management interface.
3.  The attacker identifies that the OpenVPN configuration allows for user-defined scripts.
4.  The attacker crafts a malicious OpenVPN configuration file or injects malicious commands via existing configuration options. This configuration contains embedded shell commands designed for execution on the PLC.
5.  The attacker uploads or applies the modified OpenVPN configuration to the WAGO PLC through the web interface.
6.  The WAGO PLC processes the OpenVPN configuration, leading to the execution of the attacker-supplied shell commands.
7.  The attacker achieves arbitrary code execution on the underlying operating system of the WAGO PLC.
8.  The attacker can then use this initial foothold to perform further actions, such as deploying malware, exfiltrating sensitive information, or disrupting industrial processes.

## Impact

Successful exploitation of CVE-2024-1490 allows an attacker to execute arbitrary code on a WAGO PLC. This can lead to complete compromise of the device, potentially affecting the industrial processes it controls. An attacker could disrupt operations, manipulate data, or use the compromised PLC as a pivot point for further attacks within the industrial network. The severity of the impact depends on the role of the compromised PLC within the industrial environment, potentially leading to significant financial losses, safety incidents, or reputational damage.

## Recommendation

*   Restrict access to the WAGO PLC's web-based management interface by enforcing strong authentication and authorization mechanisms to prevent unauthorized access (refer to CVE-2024-1490).
*   Disable or restrict the use of user-defined scripts within the OpenVPN configuration to mitigate the risk of command injection (refer to CVE-2024-1490).
*   Monitor web server logs for suspicious activity related to OpenVPN configuration changes, looking for unusual POST requests or configuration parameters (see "rules" section below).
*   Implement regular security audits of WAGO PLC configurations, focusing on OpenVPN settings and user-defined scripts (refer to CVE-2024-1490).
*   Review and apply the security recommendations provided by CERT VDE in their advisory, available at https://certvde.com/de/advisories/VDE-2024-008.
