---
title: JetBrains TeamCity CVE-2023-42793 RCE Attempt
slug: 2024-01-02-jetbrains-teamcity-rce
description: An attacker attempts to exploit the CVE-2023-42793 vulnerability in JetBrains TeamCity On-Premises by sending a malicious POST request to gain administrative access and achieve remote code execution.
date: "2024-01-02T12:00:00Z"
lastmod: "2026-08-28T08:24:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FLOJBOJ-CVE-2023-42793&utm_source=rss&utm_medium=rss
tags:
  - jetbrains
  - teamcity
  - rce
  - cve-2023-42793
vendors:
  - JetBrains
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2023-42793
    cvss: 9.8
    epss: 0.99979
references:
  - https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/
  - https://www.sonarsource.com/blog/teamcity-vulnerability/
  - https://github.com/rapid7/metasploit-framework/pull/18408
  - https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FLOJBOJ-CVE-2023-42793&utm_source=rss&utm_medium=rss
rules:
  - title: Detect TeamCity CVE-2023-42793 Attempt
    description: Detects attempts to exploit CVE-2023-42793 in JetBrains TeamCity On-Premises by identifying suspicious POST requests to the RPC2 endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect TeamCity CVE-2023-42793 Exploitation via User Agent
    description: Detects exploitation of CVE-2023-42793 by looking for specific user agents often used in exploitation attempts.
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
updates:
  - at: "2026-08-28T08:24:19Z"
    level: L2
    summary: poc_available; added CVE-2023-42793
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FLOJBOJ-CVE-2023-42793&utm_source=rss&utm_medium=rss
---

The CVE-2023-42793 vulnerability in JetBrains TeamCity On-Premises allows an unauthenticated attacker to perform remote code execution. This vulnerability affects versions prior to 2023.05.4. The vulnerability arises from improper handling of authentication tokens, specifically related to the `/app/rest/users/id:1/tokens/RPC2` endpoint. An attacker can exploit this by sending a specially crafted POST request. Successful exploitation grants the attacker administrative privileges, potentially leading to full system compromise, data breaches, and further unauthorized access within the network. Detection efforts should focus on monitoring web traffic for suspicious POST requests targeting the identified endpoint.

## Attack Chain

1.  The attacker identifies a vulnerable JetBrains TeamCity On-Premises instance running a version prior to 2023.05.4.
2.  The attacker crafts a malicious POST request targeting the `/app/rest/users/id:1/tokens/RPC2` endpoint.
3.  The attacker sends the crafted POST request to the vulnerable TeamCity server.
4.  The TeamCity server improperly processes the request due to the CVE-2023-42793 vulnerability.
5.  The attacker gains unauthorized administrative access to the TeamCity server.
6.  The attacker leverages the gained administrative access to execute arbitrary code on the server.
7.  The attacker establishes persistence on the compromised TeamCity server.
8.  The attacker uses the compromised TeamCity server as a pivot point to move laterally within the network and compromise other systems or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2023-42793 can lead to a complete compromise of the JetBrains TeamCity server. This includes unauthorized access to sensitive project data, build configurations, and potentially source code. Furthermore, attackers can leverage the compromised TeamCity server as a stepping stone to infiltrate other systems within the organization's network, leading to widespread data breaches, ransomware deployment, or intellectual property theft. This vulnerability impacts organizations that rely on JetBrains TeamCity for their CI/CD pipeline.

## Recommendation

*   Deploy the Sigma rule `Detect TeamCity CVE-2023-42793 Attempt` to your SIEM to detect exploitation attempts based on HTTP requests.
*   Inspect web server logs for POST requests to `/app/rest/users/id:1/tokens/RPC2` with a 200 status code, as highlighted in the main search query.
*   Apply filters to the Sigma rule `Detect TeamCity CVE-2023-42793 Attempt` to reduce false positives, focusing on uncommon user agents as described in the "known_false_positives" section.
*   Immediately patch all JetBrains TeamCity On-Premises instances to version 2023.05.4 or later to remediate the CVE-2023-42793 vulnerability, as advised by JetBrains.
