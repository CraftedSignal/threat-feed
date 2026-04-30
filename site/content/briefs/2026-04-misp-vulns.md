---
title: Multiple Vulnerabilities in MISP Threat Intelligence Platform
slug: 2026-04-misp-vulns
description: Multiple vulnerabilities in MISP versions prior to 2.5.37 allow attackers to perform privilege escalation, SQL injection (SQLi), and security policy bypass.
date: "2026-04-30T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - misp
  - vulnerability
  - sqli
  - privilege-escalation
  - security-policy-bypass
vendors:
  - MISP
products:
  - MISP < 2.5.37
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0515/
  - https://www.misp-project.org/security/
rules:
  - title: Detect Potential SQL Injection Attempts Against MISP
    description: Detects potential SQL injection attempts against MISP by monitoring HTTP request parameters for common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Access Attempts to MISP Admin Interface
    description: Detects attempts to access the MISP admin interface from unusual IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities have been discovered in MISP (Malware Information Sharing Platform and Threat Sharing) versions prior to 2.5.37. These flaws could allow a remote attacker to perform a variety of malicious actions, including escalating privileges to gain unauthorized access, injecting SQL code to potentially read or modify database contents, and bypassing existing security policies to execute restricted operations. These vulnerabilities pose a significant risk to organizations using MISP for threat intelligence, potentially leading to data breaches, unauthorized access to sensitive information, or disruption of threat intelligence operations. Users should upgrade to version 2.5.37 or later as soon as possible.

## Attack Chain

1. An attacker identifies a vulnerable MISP instance running a version prior to 2.5.37.
2. The attacker crafts a malicious SQL injection payload designed to exploit a SQLi vulnerability within the MISP application, potentially targeting input fields or API endpoints.
3. The attacker sends the crafted SQL injection payload to the vulnerable MISP instance through a web request or API call.
4. The MISP application improperly processes the malicious SQL payload, leading to the execution of attacker-controlled SQL commands against the underlying database.
5. The attacker exploits a privilege escalation vulnerability to gain elevated privileges within the MISP application, potentially bypassing access controls.
6. The attacker leverages the security policy bypass vulnerability to circumvent security restrictions and execute unauthorized actions within the MISP system.
7. The attacker gains unauthorized access to sensitive data stored within the MISP instance, such as threat intelligence reports, indicators of compromise (IOCs), or user credentials.
8. The attacker exfiltrates the stolen data or uses the compromised system to launch further attacks against other systems or organizations.

## Impact

Successful exploitation of these vulnerabilities could allow an attacker to gain unauthorized access to sensitive threat intelligence data stored within MISP, potentially impacting organizations relying on MISP for security operations. An attacker could steal sensitive data, modify existing intelligence, or inject false information, impacting trust in the platform. While the number of victims is not specified in the report, any organization using a vulnerable version of MISP is at risk. The severity of impact would depend on the sensitivity of the data stored within the compromised MISP instance.

## Recommendation

*   Upgrade MISP to version 2.5.37 or later to remediate the vulnerabilities as per the vendor's security bulletin.
*   Deploy web application firewall (WAF) rules to detect and block SQL injection attempts targeting MISP, mitigating potential SQLi exploitation.
*   Monitor MISP logs (category `webserver`, product `linux`) for suspicious activity, such as unexpected SQL errors or unauthorized access attempts, to identify potential exploitation attempts.
