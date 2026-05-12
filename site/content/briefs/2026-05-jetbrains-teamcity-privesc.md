---
title: JetBrains TeamCity On-Premises Privilege Escalation Vulnerability
slug: 2026-05-jetbrains-teamcity-privesc
description: A remote, authenticated attacker can exploit a vulnerability in JetBrains TeamCity On-Premises to escalate privileges.
date: "2026-05-12T09:55:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - teamcity
  - webserver
vendors:
  - JetBrains
products:
  - TeamCity On-Premises
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1460
rules:
  - title: Detect Potential TeamCity Privilege Escalation Attempts via Web Requests
    description: Detects suspicious HTTP requests indicative of privilege escalation attempts in JetBrains TeamCity On-Premises based on request characteristics.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect TeamCity User Impersonation Attempts via Web Requests
    description: Detects suspicious HTTP requests indicative of user impersonation attempts in JetBrains TeamCity On-Premises based on request characteristics.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists in JetBrains TeamCity On-Premises that allows a remote, authenticated attacker to escalate their privileges within the application. The specific nature of the vulnerability is not detailed, but its exploitation could lead to unauthorized access to sensitive data, modification of system configurations, or execution of arbitrary code within the TeamCity environment. This issue affects on-premises installations, potentially impacting organizations that rely on TeamCity for their continuous integration and continuous delivery (CI/CD) processes. Defenders should investigate their TeamCity deployment for unusual account activity and apply the appropriate patches from JetBrains when available.

## Attack Chain

1. The attacker gains initial access to a TeamCity On-Premises instance through legitimate credentials (e.g., compromised account, insider threat).
2. The attacker identifies a privilege escalation vulnerability within the TeamCity application.
3. The attacker crafts a specific HTTP request to the TeamCity server, exploiting the vulnerability. This request might involve manipulating parameters, exploiting API endpoints, or injecting malicious code.
4. The TeamCity server processes the malicious request without proper authorization checks.
5. The attacker successfully escalates their privileges, gaining access to administrative functions or higher-level permissions.
6. The attacker leverages the elevated privileges to access sensitive information, such as build configurations, secrets, or source code.
7. The attacker modifies build configurations to inject malicious code into software builds, compromising the software supply chain.
8. The attacker exfiltrates sensitive data or uses the compromised system as a pivot point for further attacks within the network.

## Impact

Successful exploitation of this vulnerability could allow an attacker to gain complete control over the TeamCity instance, leading to unauthorized access to sensitive data, modification of build processes, and potential compromise of the entire software supply chain. The number of affected organizations is unknown, but the impact could be significant for those relying on TeamCity for their CI/CD pipeline. This can lead to data breaches, code injection attacks, and disruption of software development processes.

## Recommendation

*   Monitor TeamCity logs (category: webserver) for suspicious HTTP requests targeting TeamCity endpoints to detect potential exploitation attempts.
*   Implement the Sigma rule to detect common privilege escalation attempts via web requests.
*   Apply any available patches or updates released by JetBrains for TeamCity On-Premises to address the vulnerability.
*   Review and enforce strong authentication and authorization policies for TeamCity users to mitigate the risk of compromised accounts.
