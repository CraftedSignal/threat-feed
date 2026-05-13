---
title: F5 BIG-IP CVE-2026-42924 iControl SOAP SNMP Configuration Privilege Escalation
slug: 2026-05-f5-snmp-privesc
description: CVE-2026-42924 allows an authenticated attacker with Resource Administrator or Administrator privileges to escalate privileges by creating malicious SNMP configuration objects through iControl SOAP.
date: "2026-05-13T16:26:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - snmp
  - f5
  - cve-2026-42924
vendors:
  - F5 Networks
products:
  - BIG-IP
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-42924
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42924
  - https://my.f5.com/manage/s/article/K000160926
rules:
  - title: Detect Suspicious iControl SOAP SNMP Configuration Creation
    description: Detects suspicious iControl SOAP API requests used to create SNMP configuration objects, potentially indicating CVE-2026-42924 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-42924 is a privilege escalation vulnerability in F5 BIG-IP. An authenticated attacker with either the Resource Administrator or Administrator role can exploit this flaw by crafting malicious SNMP configuration objects via iControl SOAP. Successful exploitation leads to privilege escalation within the BIG-IP system. The vulnerability is triggered due to insufficient validation or sanitization when creating SNMP configuration objects. This allows an attacker to insert malicious configurations, leading to elevated privileges. Software versions that have reached End of Technical Support (EoTS) are not evaluated for this vulnerability.

## Attack Chain

1. The attacker authenticates to the F5 BIG-IP system with Resource Administrator or Administrator privileges.
2. The attacker crafts a malicious SNMP configuration object. This object contains commands or configurations designed to escalate privileges.
3. The attacker uses iControl SOAP API to send a request to create the malicious SNMP configuration object.
4. The iControl SOAP API processes the request without proper validation of the SNMP configuration object.
5. The malicious SNMP configuration object is created within the BIG-IP system.
6. The malicious SNMP configuration allows the attacker to execute commands with elevated privileges.
7. The attacker leverages the escalated privileges to perform unauthorized actions on the BIG-IP system.

## Impact

Successful exploitation of CVE-2026-42924 allows an attacker to gain elevated privileges on the F5 BIG-IP system. This can lead to full control of the device, potentially allowing the attacker to intercept network traffic, modify configurations, or disrupt services. The specific impact depends on the attacker's objectives and the configuration of the BIG-IP system.

## Recommendation

*   Apply the security patch or upgrade to a fixed version of F5 BIG-IP to address CVE-2026-42924.
*   Monitor iControl SOAP API requests for suspicious activity related to SNMP configuration creation (see rule "Detect Suspicious iControl SOAP SNMP Configuration Creation").
*   Implement strict access controls to limit the number of users with Resource Administrator or Administrator privileges.
*   Audit existing SNMP configurations for any unauthorized or malicious entries.
*   Review F5's advisory K000160926 for mitigation and remediation guidance.
