---
title: Confluence Unauthenticated Remote Code Execution (CVE-2022-26134)
slug: 2024-01-confluence-rce
description: Exploitation of CVE-2022-26134, an unauthenticated remote code execution vulnerability in Atlassian Confluence, allows attackers to execute arbitrary code on vulnerable servers, potentially leading to complete system compromise.
date: "2024-01-03T12:00:00Z"
lastmod: "2026-09-03T01:47:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:*:*:*
  - cpe:2.3:a:atlassian:confluence_data_center:7.18.0:*:*:*:*:*:*:*
  - cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:atlassian:confluence_server:7.18.0:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ARCHANCHOUDHURY-CONFLUENCE-CVE-2022-26134&utm_source=rss&utm_medium=rss
tags:
  - confluence
  - rce
  - cve-2022-26134
  - webserver
vendors:
  - Atlassian
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
cves:
  - id: CVE-2022-26134
    cvss: 9.8
    epss: 0.99999
references:
  - https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html
  - https://www.splunk.com/en_us/blog/security/atlassian-confluence-vulnerability-cve-2022-26134.html
  - https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/
  - https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ARCHANCHOUDHURY-CONFLUENCE-CVE-2022-26134&utm_source=rss&utm_medium=rss
iocs:
  - type: hash_sha256
    value: f39b321472b8dac2452e4c0bc687cb5aa401ac6687520fdc9fd523a17477886d
  - type: hash_md5
    value: f8df4dd46f02dc86d37d46cf4793e036
ioc_counts:
  hash_md5: 1
  hash_sha256: 1
rules:
  - title: Detect Confluence CVE-2022-26134 Exploitation Attempts
    description: Detects exploitation attempts of CVE-2022-26134 in Atlassian Confluence by identifying suspicious URL patterns indicative of OGNL injection.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Confluence CVE-2022-26134 Exploitation with ProcessBuilder
    description: Detects exploitation attempts of CVE-2022-26134 in Atlassian Confluence by identifying the use of ProcessBuilder in the request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-09-03T01:47:42Z"
    level: L2
    summary: poc_available; added CVE-2022-26134
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ARCHANCHOUDHURY-CONFLUENCE-CVE-2022-26134&utm_source=rss&utm_medium=rss
---

CVE-2022-26134 is an unauthenticated remote code execution vulnerability affecting Atlassian Confluence Server and Data Center. Publicly disclosed in June 2022, this vulnerability allows unauthenticated attackers to execute arbitrary code on vulnerable Confluence servers. The vulnerability stems from insufficient input validation, allowing OGNL injection via specially crafted HTTP requests. Exploitation attempts were observed shortly after the vulnerability became public, with attackers leveraging it to deploy web shells, cryptominers, and other malicious payloads. This vulnerability has been widely exploited, making it a significant threat to organizations using affected Confluence versions. Successful exploitation grants attackers complete control over the Confluence server, enabling data theft, lateral movement, and further malicious activities within the network.

## Attack Chain

1.  The attacker sends a crafted HTTP request to the Confluence server targeting a vulnerable endpoint, such as a page or a component.
2.  The malicious request contains an OGNL expression injected within a URL parameter (e.g., using `${}` sequences or URL-encoded variations like `%2F%7B`).
3.  The Confluence server processes the request and executes the injected OGNL expression due to insufficient input validation.
4.  The OGNL expression leverages Java runtime execution capabilities (e.g., `java.lang.Runtime.getRuntime().exec()`) to execute arbitrary commands on the server.
5.  The attacker uses the executed commands to download and execute a malicious payload from an external server using tools like `wget` or `curl`.
6.  The malicious payload installs a web shell (e.g., a JSP file) on the Confluence server, providing persistent remote access.
7.  The attacker uses the web shell to further explore the compromised system, steal sensitive data, or move laterally within the network.
8.  The attacker may deploy cryptominers, ransomware, or other malicious software, impacting the availability and integrity of the Confluence server and potentially the entire network.

## Impact

Successful exploitation of CVE-2022-26134 allows unauthenticated attackers to gain complete control over vulnerable Atlassian Confluence servers. This can lead to data breaches, with sensitive information stored in Confluence exposed to unauthorized access. Attackers can also use compromised Confluence servers as a beachhead for lateral movement, expanding their reach within the network. Observed consequences have included the deployment of web shells, cryptominers, and ransomware. The widespread exploitation of this vulnerability has affected numerous organizations across various sectors, resulting in significant financial and reputational damage.

## Recommendation

*   Apply the latest security patches released by Atlassian to address CVE-2022-26134 on all Confluence servers immediately.
*   Deploy the Sigma rule "Detect Confluence CVE-2022-26134 Exploitation Attempts" to your SIEM to identify suspicious requests containing OGNL injection patterns.
*   Implement the Sigma rule "Detect Confluence CVE-2022-26134 Exploitation with ProcessBuilder" to identify exploit attempts leveraging `ProcessBuilder`.
*   Monitor web server logs for requests containing suspicious URL patterns, particularly those including `${`, `%2F%7B`, `org.apache.commons.io.IOUtils`, and `java.lang.Runtime`.
*   Review and restrict network access to Confluence servers, limiting connections to only trusted sources.
