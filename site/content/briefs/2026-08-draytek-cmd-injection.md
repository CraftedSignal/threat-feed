---
title: Critical OS Command Injection in DrayTek VigorSwitch
slug: 2026-08-draytek-cmd-injection
description: Multiple DrayTek VigorSwitch models contain a pre-authentication command injection vulnerability (CVE-2026-71921) in the setget.cgi interface that allows unauthenticated remote attackers to execute arbitrary commands as root.
date: "2026-08-24T20:02:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - remote-code-execution
  - network-infrastructure
vendors:
  - DrayTek
products:
  - VigorSwitch G2540xs
  - VigorSwitch P2540xs
  - VigorSwitch FX2120
  - VigorSwitch G2282x
  - VigorSwitch P2282x
  - VigorSwitch Q2300x
  - VigorSwitch PQ2300xb
  - VigorSwitch G2542x
  - VigorSwitch P2542x
  - VigorSwitch P2542xh
  - VigorSwitch PX2060
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote attacker can trigger this vulnerability via crafted input to execute arbitrary commands with root privileges.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability is caused by insufficient filtering of the pass field before command execution.
    confidence_band: high
cves:
  - id: CVE-2026-71921
    cvss: 9.8
references:
  - https://www.draytek.com/about/security-advisory/multiple-vulnerabilities-in-vigorswitch-series-august-2026/
  - https://www.vulncheck.com/advisories/draytek-vigorswitch-multiple-models-pre-authentication-os-command-injection-via-setget-cgi
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71921
rules:
  - title: Detects CVE-2026-71921 Exploitation - OS Command Injection in setget.cgi
    description: Detects exploitation attempts against the DrayTek VigorSwitch setget.cgi interface where the 'pass' parameter contains common shell metacharacters.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

DrayTek has disclosed a critical command injection vulnerability, identified as CVE-2026-71921, affecting multiple models within the VigorSwitch series. The vulnerability is located in the setget.cgi interface, which fails to properly sanitize the 'pass' parameter before passing it to an underlying system process. An unauthenticated remote attacker can exploit this flaw by sending a crafted HTTP request containing shell metacharacters, leading to arbitrary command execution with root-level privileges on the affected networking equipment. Given that these devices often operate at the perimeter or core of internal networks, successful exploitation grants the attacker persistent control over the network infrastructure. Defenders should prioritize updating firmware for all affected VigorSwitch units listed below.

## Impact

Successful exploitation of CVE-2026-71921 results in complete system compromise, allowing an attacker to gain root access to the affected switch. This facilitates unauthorized network traffic interception, pivoting into internal network segments, or the installation of persistent backdoors on the device. Numerous models are impacted, spanning various firmware versions, creating a widespread exposure for organizations utilizing DrayTek infrastructure.

## Recommendation

- Immediately update firmware on all affected DrayTek VigorSwitch models to the non-vulnerable versions specified in the vendor security advisory.
- Apply access control lists (ACLs) to restrict management interface access (setget.cgi) to trusted internal management subnets only.
- Deploy the Sigma rule provided below to identify exploitation attempts targeting the setget.cgi interface via web logs.
