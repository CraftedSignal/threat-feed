---
title: Multiple Vulnerabilities in Wazuh Allow for Code Execution and Data Manipulation
slug: 2026-05-wazuh-multiple-vulnerabilities
description: Multiple vulnerabilities in Wazuh allow an attacker to perform a denial of service attack, execute arbitrary code, manipulate data, disclose confidential information, or bypass security measures.
date: "2026-04-30T09:09:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - siem
  - xdr
vendors:
  - Wazuh
products:
  - Wazuh
affected_os:
  - linux
  - windows
  - macos
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1295
rules:
  - title: Wazuh Server Suspicious Process
    description: Detects suspicious processes spawned by the Wazuh server, potentially indicating code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Wazuh Agent Outbound Connection
    description: Detects outbound network connections from Wazuh agent processes.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Multiple vulnerabilities have been identified within Wazuh, a widely used security information and event management (SIEM) and extended detection and response (XDR) platform. While the specific CVEs and technical details remain undisclosed in this initial advisory, the potential impact is significant. A remote, unauthenticated attacker could exploit these vulnerabilities to achieve a range of malicious outcomes, including denial of service, arbitrary code execution, data manipulation, sensitive information disclosure, and the circumvention of security controls. The vulnerabilities affect Wazuh installations across Linux, Windows, and macOS environments. Due to the broad functionality of Wazuh in security monitoring and incident response, successful exploitation could lead to widespread compromise within targeted organizations.

## Attack Chain

1.  The attacker identifies a vulnerable Wazuh instance accessible over the network.
2.  The attacker exploits a vulnerability to bypass authentication or authorization controls.
3.  The attacker leverages an arbitrary code execution vulnerability to gain remote shell access to the Wazuh server.
4.  The attacker escalates privileges to gain root or SYSTEM level access on the Wazuh server.
5.  The attacker manipulates Wazuh configuration files to disable security alerts or modify monitoring rules.
6.  The attacker injects malicious code into Wazuh agents to compromise endpoints managed by the platform.
7.  The attacker uses the compromised Wazuh infrastructure to exfiltrate sensitive data collected by the platform.
8.  The attacker launches denial-of-service attacks against monitored systems using compromised Wazuh agents.

## Impact

Successful exploitation of these vulnerabilities could have severe consequences. An attacker could gain complete control over the Wazuh platform, disabling security monitoring, manipulating security data, and compromising monitored endpoints. This could lead to undetected data breaches, widespread malware infections, and significant disruption of IT operations. The lack of specific vulnerability information makes it difficult to assess the exact scope of impact, but the wide deployment of Wazuh in security-critical environments means that numerous organizations are potentially at risk.

## Recommendation

*   Monitor Wazuh server process creation for unusual child processes that might indicate exploitation, using the "Wazuh Server Suspicious Process" Sigma rule.
*   Inspect Wazuh server logs for authentication bypass attempts and unauthorized configuration changes.
*   Block network connections originating from newly created Wazuh agent processes using the "Wazuh Agent Outbound Connection" Sigma rule, to prevent lateral movement.
