---
title: F5 BIG-IP APM CVE-2025-53521 Reclassified as Actively Exploited Unauthenticated RCE
slug: 2026-04-f5-big-ip-rce
description: F5 has reclassified CVE-2025-53521, a vulnerability in BIG-IP APM, as a critical unauthenticated remote code execution vulnerability and reports it is being actively exploited in the wild.
date: "2026-04-01T12:00:00Z"
severities:
  - critical
exploited: true
type: threat
types:
  - threat
tags:
  - f5
  - big-ip
  - apm
  - cve-2025-53521
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2025-53521
    cvss: 9.8
    epss: 0.07452
references:
  - https://arcticwolf.com/resources/blog/cve-2025-53521/
rules:
  - title: Detect CVE-2025-53521 Exploitation Attempt via HTTP Request
    description: Detects potential exploitation attempts of CVE-2025-53521 by monitoring for suspicious HTTP requests to BIG-IP APM.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect CVE-2025-53521 Exploitation Attempt via HTTP POST Request
    description: Detects potential exploitation attempts of CVE-2025-53521 by monitoring for suspicious HTTP POST requests to BIG-IP APM.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 28, 2026, F5 issued a revised security advisory regarding CVE-2025-53521, a vulnerability affecting BIG-IP APM. Initially disclosed in October 2025 and categorized as a medium-severity denial-of-service (DoS) issue, it has been reclassified as a critical remote code execution (RCE) vulnerability. F5 has confirmed that CVE-2025-53521 is now being actively exploited by unauthenticated attackers. The updated classification significantly elevates the risk associated with this vulnerability, necessitating immediate action from organizations utilizing affected BIG-IP APM instances to prevent potential system compromise and unauthorized access.

## Attack Chain

Given the nature of an unauthenticated RCE vulnerability, the following attack chain is likely:

1.  **Initial Access:** An unauthenticated attacker sends a specially crafted HTTP request to a vulnerable BIG-IP APM endpoint.
2.  **Vulnerability Trigger:** The malicious request exploits CVE-2025-53521, bypassing authentication checks.
3.  **Code Execution:** The successful exploit allows the attacker to execute arbitrary code on the BIG-IP APM system with the privileges of the affected service.
4.  **Privilege Escalation (Optional):** The attacker may attempt to escalate privileges to gain root or administrator access. This could involve exploiting other vulnerabilities or leveraging misconfigurations.
5.  **System Compromise:** With code execution, the attacker gains control over the BIG-IP APM system.
6.  **Lateral Movement/Data Exfiltration/System Tampering:** The attacker can use the compromised system as a pivot point to access other internal resources, exfiltrate sensitive data, or tamper with system configurations.
7.  **Persistence:** The attacker might establish persistent access by installing backdoors or creating rogue accounts.

## Impact

Successful exploitation of CVE-2025-53521 can lead to complete compromise of the affected BIG-IP APM system. This can result in unauthorized access to sensitive data, disruption of critical services, and potential lateral movement to other systems within the network. Given the reclassification to critical severity and active exploitation, the potential for widespread damage is significant. Organizations in all sectors using vulnerable BIG-IP APM instances are at risk.

## Recommendation

*   Immediately patch CVE-2025-53521 on all affected BIG-IP APM systems with the latest security updates from F5.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts.
*   Monitor web server logs for suspicious HTTP requests targeting BIG-IP APM endpoints that may indicate exploitation attempts. This can be used to refine detection rules and identify potentially compromised systems.
