---
title: Cisco Catalyst SD-WAN Manager Multiple Vulnerabilities
slug: 2026-04-cisco-sdwan-vulns
description: Multiple vulnerabilities in Cisco Catalyst SD-WAN Manager allow a remote, anonymous, or local attacker to gain administrator privileges, bypass authentication, execute commands with Netadmin rights, read sensitive system information, and overwrite arbitrary files.
date: "2026-04-21T08:08:56Z"
severities:
  - critical
tags:
  - cisco
  - sdwan
  - vulnerability
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0516
rules:
  - title: Detect Suspicious Outbound Connection from SD-WAN Manager
    description: Detects suspicious outbound network connections originating from the SD-WAN Manager that may indicate compromise or unauthorized activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Unauthorized Configuration Change via SD-WAN Manager
    description: Detects unauthorized or suspicious configuration changes made through the SD-WAN Manager interface.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities exist within the Cisco Catalyst SD-WAN Manager software. These vulnerabilities can be exploited by remote, anonymous, or local attackers. Successful exploitation allows attackers to perform a range of malicious activities. These include escalating privileges to administrator level, circumventing authentication mechanisms, executing arbitrary commands with Netadmin-level privileges, accessing sensitive system information, and overwriting arbitrary files on the affected…
