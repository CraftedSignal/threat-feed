---
title: Windows Remote Desktop Licensing Service Privilege Escalation Vulnerability (CVE-2026-26160)
slug: 2026-04-rdls-privesc
description: CVE-2026-26160 is a privilege escalation vulnerability in the Windows Remote Desktop Licensing Service due to missing authentication, allowing a local attacker to gain elevated privileges.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - privilege escalation
  - rdls
  - cve-2026-26160
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26160
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26160
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26160
rules:
  - title: Suspicious Process interacting with Remote Desktop Licensing Service
    description: Detects suspicious processes interacting with the Remote Desktop Licensing Service, potentially indicating exploitation of CVE-2026-26160.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Remote Desktop Licensing Service Crash
    description: Detects events indicating a crash or abnormal termination of the Remote Desktop Licensing Service, which could be a result of exploiting CVE-2026-26160.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - system
      - windows
rules_count: 2
---

CVE-2026-26160 is a critical vulnerability affecting the Windows Remote Desktop Licensing Service (RDLS). This vulnerability stems from a missing authentication check for a critical function within the service. A locally authenticated attacker can exploit this flaw to elevate their privileges on the system. The vulnerability was publicly disclosed on April 14, 2026. The scope of the vulnerability is limited to local privilege escalation, meaning an attacker needs existing access to the system to exploit it. Successful exploitation could allow an attacker to perform actions with elevated permissions, potentially leading to complete system compromise.

## Attack Chain

1.  The attacker gains initial access to the target Windows system with standard user privileges.
2.  The attacker identifies the vulnerable Remote Desktop Licensing Service.
3.  The attacker crafts a malicious request to the RDLS API, exploiting the missing authentication vulnerability (CVE-2026-26160).
4.  The attacker sends the crafted request to the RDLS endpoint.
5.  Due to the missing authentication check, the RDLS processes the request without proper validation.
6.  The RDLS executes the attacker's command with elevated privileges.
7.  The attacker uses the elevated privileges to modify system settings or install malicious software.
8.  The attacker achieves persistence and full control of the compromised system.

## Impact

Successful exploitation of CVE-2026-26160 allows a local attacker to escalate their privileges to SYSTEM. While the vulnerability requires local access, it can be chained with other vulnerabilities or social engineering tactics to compromise systems remotely. The impact includes unauthorized data access, system modification, and potential installation of malware, leading to a complete compromise of the affected Windows system. The vulnerability affects any system where the Remote Desktop Licensing Service is enabled, impacting a wide range of Windows environments.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-26160 as soon as possible. Refer to the Microsoft Security Response Center advisory ([https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26160](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26160)).
*   Monitor for suspicious processes interacting with the Remote Desktop Licensing Service that may indicate exploitation attempts, using the Sigma rules provided below.
*   Review and harden local account security policies to limit the initial attack surface and reduce the likelihood of successful exploitation.
