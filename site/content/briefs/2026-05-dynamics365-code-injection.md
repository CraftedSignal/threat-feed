---
title: 'CVE-2026-42898: Microsoft Dynamics 365 (on-premises) Code Injection Vulnerability'
slug: 2026-05-dynamics365-code-injection
description: CVE-2026-42898 is a code injection vulnerability in Microsoft Dynamics 365 (on-premises) that allows an authorized attacker to execute arbitrary code over a network.
date: "2026-05-12T18:42:53Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - code injection
  - dynamics 365
  - cve-2026-42898
  - web application
  - execution
vendors:
  - Microsoft
products:
  - Dynamics 365 (on-premises)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Code Injection
cves:
  - id: CVE-2026-42898
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42898
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42898
rules:
  - title: Detects CVE-2026-42898 Exploitation — Suspicious URI Parameters
    description: Detects CVE-2026-42898 exploitation attempts via suspicious characters in URI parameters targeting Dynamics 365 (on-premises)
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
    data_sources:
      - webserver
  - title: Detects CVE-2026-42898 Exploitation — Suspicious POST Request Body
    description: Detects CVE-2026-42898 exploitation attempts via suspicious characters in POST request bodies targeting Dynamics 365 (on-premises)
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-42898 is a critical code injection vulnerability affecting Microsoft Dynamics 365 (on-premises). This vulnerability allows an authorized attacker with network access to inject and execute arbitrary code on the affected system. The vulnerability stems from improper control of code generation within the Dynamics 365 application. Successful exploitation can lead to complete system compromise, data breaches, and unauthorized access to sensitive information. Defenders should prioritize patching and consider implementing detection measures to identify potential exploitation attempts. The vulnerability was published on 2026-05-12 and poses a significant threat to organizations using on-premises deployments of Dynamics 365.

## Attack Chain

1. An authorized attacker gains network access to the Dynamics 365 (on-premises) environment.
2. The attacker authenticates to the Dynamics 365 application.
3. The attacker crafts a malicious request containing injected code.
4. The malicious request is sent to a vulnerable endpoint within the Dynamics 365 application.
5. The application improperly processes the request, leading to code generation based on the attacker-controlled input.
6. The injected code is executed within the context of the Dynamics 365 application.
7. The attacker gains control of the Dynamics 365 server.
8. The attacker leverages their access to compromise other systems on the network or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-42898 allows an attacker to execute arbitrary code on the Microsoft Dynamics 365 (on-premises) server. This can lead to a complete compromise of the system, potentially affecting all data and processes managed by Dynamics 365. Impact includes data breaches, financial losses, and reputational damage. Given the widespread use of Dynamics 365 in managing customer relationships and business operations, a successful attack could have significant consequences for affected organizations.

## Recommendation

*   Apply the patch provided by Microsoft to address CVE-2026-42898 as soon as possible to prevent exploitation.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts in real-time.
*   Monitor network traffic for suspicious requests to Dynamics 365 servers, specifically looking for patterns indicative of code injection (see Sigma rules).
*   Review user access controls within Dynamics 365 to ensure least privilege and limit the impact of potential compromises.
*   Implement web application firewall (WAF) rules to filter out malicious requests targeting Dynamics 365.
