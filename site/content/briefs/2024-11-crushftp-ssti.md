---
title: CrushFTP Server-Side Template Injection Exploitation
slug: 2024-11-crushftp-ssti
description: Exploitation of CVE-2024-4040, a server-side template injection vulnerability in CrushFTP, allows unauthenticated remote attackers to access files, circumvent authentication, and execute arbitrary commands.
date: "2024-11-14T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - crushftp
  - ssti
  - cve-2024-4040
vendors:
  - CrushFTP
products:
  - CrushFTP Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
cves:
  - id: CVE-2024-4040
    cvss: 9.8
    epss: 0.99539
references:
  - https://github.com/airbus-cert/CVE-2024-4040
  - https://www.bleepingcomputer.com/news/security/crushftp-warns-users-to-patch-exploited-zero-day-immediately/
rules:
  - title: Detect CrushFTP Server Side Template Injection Attempt
    description: Detects attempts to exploit the CrushFTP server-side template injection vulnerability (CVE-2024-4040) by monitoring for specific patterns in the URI query.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1608.001
    data_sources:
      - webserver
      - linux
  - title: Detect CrushFTP Exploitation via Session Logs
    description: This rule detects potential exploitation of CrushFTP by analyzing session logs for suspicious READ/WROTE actions with specific keywords.
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

The CVE-2024-4040 vulnerability is a server-side template injection flaw affecting CrushFTP versions up to 10.7.1 and 11.1.0. Discovered in April 2024, this vulnerability allows unauthenticated remote attackers to bypass the VFS Sandbox, potentially gaining access to sensitive files and executing arbitrary commands on the affected server. The vulnerability stems from improper handling of template processing, enabling attackers to inject malicious code into server-side templates. Successful exploitation can lead to complete system compromise, data breaches, and disruption of services. Publicly available exploits exist, making this a high-risk vulnerability that requires immediate patching. This activity is detected by analyzing CrushFTP session logs for specific exploitation patterns, focusing on HTTP requests containing malicious template injection payloads.

## Attack Chain

1.  An unauthenticated attacker sends a malicious HTTP request to a CrushFTP server.
2.  The request contains a crafted payload designed to exploit the server-side template injection vulnerability (CVE-2024-4040).
3.  The CrushFTP server processes the malicious payload without proper sanitization, interpreting it as a template directive.
4.  The injected template code allows the attacker to read files outside the VFS sandbox.
5.  The attacker leverages the file read capability to obtain sensitive information such as configuration files or user credentials.
6.  The attacker crafts further requests to execute arbitrary commands on the server.
7.  The attacker uses the executed commands to establish persistence or move laterally within the network.
8.  The attacker achieves complete system compromise, potentially leading to data exfiltration or ransomware deployment.

## Impact

Successful exploitation of CVE-2024-4040 allows attackers to gain unauthorized access to sensitive data, execute arbitrary commands, and potentially compromise the entire CrushFTP server. This can lead to data breaches, service disruption, and financial losses. While specific victim numbers are not available in the provided context, the broad install base of CrushFTP suggests a potentially wide impact across various sectors. The vulnerability is easily exploitable, amplifying the risk.

## Recommendation

*   Apply the security patches for CrushFTP versions up to 10.7.1 and 11.1.0 to address CVE-2024-4040 immediately.
*   Deploy the provided Sigma rules to your SIEM to detect ongoing exploitation attempts by monitoring CrushFTP session logs.
*   Ingest CrushFTP session logs to your SIEM to enable detection of the exploitation attempts (CrushFTP data source).
*   Review and restrict network access to CrushFTP servers to limit the attack surface (network security domain).
