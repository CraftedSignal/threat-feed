---
title: Multiple Vulnerabilities in Spring Boot Allow Authorization Bypass and Potential RCE
slug: 2026-04-spring-boot-vulns
description: Multiple vulnerabilities in Spring Boot, including CVE-2026-40976, CVE-2026-40973, and CVE-2026-40972, can allow attackers to bypass authorization, hijack sessions, or achieve remote code execution, potentially leading to data breaches and system compromise.
date: "2026-04-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - spring-boot
  - vulnerability
  - rce
  - authentication-bypass
  - session-hijacking
vendors:
  - Spring
products:
  - Spring Boot
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1105
    technique_name: Remote File Copy
cves:
  - id: CVE-2026-40976
    cvss: 9.1
  - id: CVE-2026-40973
    cvss: 7
  - id: CVE-2026-40972
    cvss: 7.5
references:
  - https://ccb.belgium.be/advisories/warning-multiple-vulnerabilities-spring-boot-patch-immediately
  - https://spring.io/security/cve-2026-40976
  - https://spring.io/security/cve-2026-40973
  - https://spring.io/security/cve-2026-40972
rules:
  - title: Detect Suspicious Access to Actuator Endpoints
    description: Detects unauthorized access attempts to sensitive Spring Boot Actuator endpoints which might indicate CVE-2026-40976 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Creation in ApplicationTemp Directory
    description: Detects suspicious file creation events within the ApplicationTemp directory which can be related to CVE-2026-40973.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A set of critical vulnerabilities has been discovered in Spring Boot, a widely used Java framework for building web applications and backend services. These vulnerabilities, including CVE-2026-40976 (CVSS 9.1), CVE-2026-40973 (CVSS 7.0), and CVE-2026-40972 (CVSS 7.5), pose a significant threat to organizations using affected versions (specifically versions before 4.0.6, 3.5.14, 3.4.16, 3.3.19, and 2.7.33). Successful exploitation could lead to unauthorized access, session hijacking, and remote code execution, impacting the confidentiality, integrity, and availability of critical business systems. The initial advisory was released by CCB Belgium on April 28, 2026, urging immediate patching.

## Attack Chain

1.  **Initial Access (CVE-2026-40976 - Authentication Bypass):** An attacker sends a crafted HTTP request to a vulnerable Spring Boot application endpoint.
2.  **Exploit Default Configuration:** If the application is servlet-based, relies on the default Spring Security filter chain, depends on spring-boot-actuator-autoconfigure, and does not depend on spring-boot-health, the default web security configuration fails to enforce authorization.
3.  **Unauthorized Access:** Due to the authorization bypass, the attacker gains unauthorized access to all application endpoints without proper authentication.
4.  **Session Hijacking (CVE-2026-40973):** A local attacker exploits the vulnerability to take control of the ApplicationTemp directory.
5.  **Code Execution (CVE-2026-40973):** Once in control of the ApplicationTemp directory, the attacker can potentially execute arbitrary code within the context of the application.
6.  **Timing Attack (CVE-2026-40972):** An attacker on the same network conducts a timing attack against the DevTools remote secret.
7.  **Remote Code Execution (CVE-2026-40972):** By successfully exploiting the timing attack, the attacker can potentially achieve remote code execution on the vulnerable server.
8.  **Impact:** The attacker gains full control of the system, allowing for data exfiltration, system compromise, and operational downtime.

## Impact

Successful exploitation of these Spring Boot vulnerabilities can lead to significant damage, including unauthorized access to sensitive data, complete system compromise, and extended operational downtime. The potential number of victims is vast, considering the widespread use of Spring Boot in various sectors including finance, healthcare, and e-commerce. If an attacker successfully exploits these vulnerabilities, they could steal sensitive customer data, disrupt critical business operations, or deploy ransomware, resulting in significant financial losses and reputational damage.

## Recommendation

*   Immediately patch Spring Boot applications to the latest versions (>=4.0.6, >=3.5.14, >=3.4.16, >=3.3.19, >=2.7.33) to address CVE-2026-40976, CVE-2026-40973, and CVE-2026-40972.
*   Deploy the Sigma rule "Detect Suspicious Access to Actuator Endpoints" to identify potential exploitation attempts targeting CVE-2026-40976 by monitoring access to sensitive actuator endpoints.
*   Upscale monitoring and detection capabilities to identify any related suspicious activity as recommended by the CCB.
*   Investigate and remediate any potentially compromised systems following the patching process.
