---
title: WS_FTP Remote Code Execution Vulnerability (CVE-2023-40044)
slug: 2024-01-wsftp-rce
description: Exploitation attempts targeting CVE-2023-40044 in WS_FTP software can lead to remote code execution via crafted HTTP POST requests, potentially allowing attackers to gain unauthorized access and compromise the affected system.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ws_ftp
  - rce
  - cve-2023-40044
  - webserver
vendors:
  - Progress
products:
  - WS_FTP Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/projectdiscovery/nuclei-templates/pull/8296/files
  - https://www.assetnote.io/resources/research/rce-in-progress-ws-ftp-ad-hoc-via-iis-http-modules-cve-2023-40044
  - https://github.com/rapid7/metasploit-framework/pull/18414
rules:
  - title: Detect WS_FTP CVE-2023-40044 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2023-40044 in WS_FTP software by identifying HTTP POST requests to the /AHT/AhtApiService.asmx/AuthUser URL.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
  - title: Detect WS_FTP AHT Endpoint Access (Partial URL)
    description: Detects access to the /AHT/ endpoint, potentially indicating reconnaissance or exploit attempts related to CVE-2023-40044.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2023-40044 is a remote code execution vulnerability affecting WS_FTP Server. The vulnerability stems from insufficient validation of user-supplied input, allowing attackers to execute arbitrary code on the server. Exploit attempts typically involve sending a specially crafted HTTP POST request to the `/AHT/AhtApiService.asmx/AuthUser` endpoint. Publicly available Metasploit modules and Nuclei templates exist to exploit this vulnerability. Successful exploitation can lead to complete system compromise, including data exfiltration, installation of backdoors, and lateral movement within the network. Defenders should prioritize patching vulnerable WS_FTP servers and implementing detection mechanisms to identify and block exploitation attempts. The Metasploit module is focused on hitting the /AHT/ endpoint, not the full /AHT/AhtApiService.asmx/AuthUser URL, which can be used for tuning detection rules.

## Attack Chain

1. The attacker identifies a vulnerable WS_FTP server exposed to the internet.
2. The attacker crafts a malicious HTTP POST request targeting the `/AHT/AhtApiService.asmx/AuthUser` endpoint.
3. The POST request contains a payload designed to exploit CVE-2023-40044 and execute arbitrary code.
4. The vulnerable WS_FTP server processes the malicious POST request without proper validation.
5. The attacker's payload is executed, allowing the attacker to gain a shell on the server.
6. The attacker leverages the shell to perform reconnaissance, identify sensitive data, and escalate privileges.
7. The attacker installs a backdoor for persistent access.
8. The attacker exfiltrates sensitive data or deploys ransomware.

## Impact

Successful exploitation of CVE-2023-40044 can lead to complete compromise of the WS_FTP server. This can result in data breaches, financial loss, reputational damage, and disruption of services. The number of victims and sectors targeted is currently unknown, but given the widespread use of WS_FTP Server, the potential impact is significant.

## Recommendation

*   Apply the latest patch for WS_FTP Server to address CVE-2023-40044 immediately.
*   Deploy the Sigma rule `Detect WS_FTP CVE-2023-40044 Exploitation Attempt` to your SIEM to identify malicious HTTP POST requests targeting the vulnerable endpoint.
*   Inspect web server logs for POST requests to `/AHT/AhtApiService.asmx/AuthUser` with a 200 status code originating from untrusted sources.
*   Monitor network traffic for suspicious outbound connections originating from WS_FTP servers.
*   Review and harden the configuration of your WS_FTP server, following security best practices.
*   Implement a web application firewall (WAF) rule to block known CVE-2023-40044 exploitation patterns.
