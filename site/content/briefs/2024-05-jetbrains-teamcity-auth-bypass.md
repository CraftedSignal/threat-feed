---
title: JetBrains TeamCity Authentication Bypass Vulnerability (CVE-2024-27198)
slug: 2024-05-jetbrains-teamcity-auth-bypass
description: Exploitation of CVE-2024-27198 in JetBrains TeamCity allows unauthenticated attackers to bypass authentication and gain administrative access by sending malicious HTTP POST requests to specific API endpoints.
date: "2024-05-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - jetbrains
  - teamcity
  - authentication-bypass
  - cve-2024-27198
vendors:
  - JetBrains
products:
  - TeamCity
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/projectdiscovery/nuclei-templates/pull/9279/files
  - https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/
  - https://blog.jetbrains.com/teamcity/2024/03/teamcity-2023-11-4-is-out/
  - https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/
rules:
  - title: TeamCity Authentication Bypass Attempt
    description: Detects attempts to exploit CVE-2024-27198 by monitoring for POST requests to specific TeamCity API endpoints.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1550.002
    data_sources:
      - webserver
      - linux
  - title: TeamCity User Creation via REST API
    description: Detects creation of new users via the TeamCity REST API, which could be indicative of CVE-2024-27198 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2024-27198 is a critical authentication bypass vulnerability affecting JetBrains TeamCity on-premises servers. Disclosed in March 2024, this vulnerability allows unauthenticated attackers to perform administrative actions by crafting specific HTTP POST requests. The vulnerability is triggered by improper handling of requests to the `/app/rest/users` and `/app/rest/users/id:1/tokens` endpoints, enabling attackers to bypass authentication checks and create new user tokens with administrative privileges. Successful exploitation grants attackers full control over the TeamCity server, potentially leading to source code compromise, supply chain attacks, and deployment of malicious software. Organizations using vulnerable versions of TeamCity are at high risk and require immediate patching and monitoring.

## Attack Chain

1.  An attacker identifies a vulnerable JetBrains TeamCity server exposed to the internet.
2.  The attacker sends a crafted HTTP POST request to the `/app/rest/users` endpoint, bypassing authentication. This request exploits the vulnerability to create a new user account.
3.  The attacker sends another HTTP POST request, this time to the `/app/rest/users/id:1/tokens` endpoint, again bypassing authentication. This creates an administrative token for the newly created user.
4.  The TeamCity server, due to the vulnerability, incorrectly processes these requests as authenticated, creating the new user and token.
5.  The attacker uses the newly created administrative token to authenticate to the TeamCity server's administrative interface.
6.  The attacker gains full administrative access to the TeamCity server.
7.  The attacker modifies build configurations, injects malicious code into build processes, or exfiltrates sensitive data such as source code and API keys.
8.  The attacker compromises the software supply chain by deploying backdoored software builds through the compromised TeamCity instance.

## Impact

Successful exploitation of CVE-2024-27198 allows attackers to gain complete control over JetBrains TeamCity servers. This can lead to the compromise of source code repositories, build artifacts, and deployment pipelines. Attackers can inject malicious code into software builds, leading to supply chain attacks affecting downstream users. Due to the sensitive nature of TeamCity deployments, a successful attack can lead to significant financial losses, reputational damage, and legal liabilities. The vulnerability poses a critical risk to organizations using affected TeamCity versions.

## Recommendation

*   Deploy the provided Sigma rule `TeamCity Authentication Bypass Attempt` to your SIEM to detect exploitation attempts (log source: `webserver`).
*   Ensure your Suricata installation is properly configured to monitor HTTP traffic, as required by the provided Suricata rule (reference: Suricata data source).
*   Monitor HTTP POST requests to `/app/rest/users` and `/app/rest/users/id:1/tokens` endpoints for suspicious activity (reference: Suricata rule).
*   Apply the latest TeamCity patch to address CVE-2024-27198 (reference: JetBrains advisory).
*   Investigate and remediate any detected exploitation attempts by reviewing affected systems and logs.
