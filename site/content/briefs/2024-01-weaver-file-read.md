---
title: Weaver E-cology Arbitrary File Read Vulnerability (CVE-2022-50992)
slug: 2024-01-weaver-file-read
description: Unauthenticated remote attackers can exploit an arbitrary file read vulnerability (CVE-2022-50992) in Weaver E-cology 9.5 versions prior to 10.52 via the XML-RPC endpoint to access sensitive files.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - cve-2022-50992
  - file-read
  - vulnerability
  - webserver
vendors:
  - Weaver (Fanwei)
products:
  - E-cology 9.5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2022-50992
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-50992
rules:
  - title: Detect Weaver E-cology File Read via XML-RPC
    description: Detects attempts to exploit the arbitrary file read vulnerability (CVE-2022-50992) in Weaver E-cology via the XML-RPC endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Path Access via HTTP GET
    description: Detects suspicious file paths in HTTP GET requests, which may indicate an attempt to exploit a file read vulnerability.
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

Weaver (Fanwei) E-cology 9.5 versions prior to 10.52 are vulnerable to an arbitrary file read vulnerability (CVE-2022-50992) within the XmlRpcServlet interface. This vulnerability is located at the XML-RPC endpoint and allows unauthenticated remote attackers to read arbitrary files on the system. The attack leverages the `WorkflowService.getAttachment` and `WorkflowService.LoadTemplateProp` methods, which can be accessed without authentication, to supply file paths. Successful exploitation enables attackers to retrieve sensitive files, including system configuration files and database credentials, from the compromised server. Exploitation evidence was first observed by the Shadowserver Foundation on 2022-12-14 (UTC), highlighting active exploitation of this vulnerability.

## Attack Chain

1.  An unauthenticated attacker identifies a Weaver E-cology 9.5 instance.
2.  The attacker sends a crafted XML-RPC request to the XmlRpcServlet endpoint.
3.  The request invokes either the `WorkflowService.getAttachment` or `WorkflowService.LoadTemplateProp` method.
4.  The attacker includes a file path to a sensitive file (e.g., `/etc/passwd`, database configuration files) as a parameter in the XML-RPC request.
5.  The vulnerable method processes the request without proper authentication or authorization checks.
6.  The server reads the content of the specified file.
7.  The server returns the file content in the XML-RPC response.
8.  The attacker parses the response to extract the contents of the sensitive file, potentially gaining access to credentials or other sensitive information.

## Impact

Successful exploitation of CVE-2022-50992 allows unauthenticated attackers to read arbitrary files on the Weaver E-cology server. This can lead to the disclosure of sensitive information, such as system configuration files, database credentials, and other confidential data. The CVSS v3.1 base score is 7.5, indicating a high severity vulnerability. This vulnerability can lead to full system compromise if database credentials are leaked.

## Recommendation

*   Upgrade Weaver E-cology instances to version 10.52 or later to remediate CVE-2022-50992.
*   Deploy the Sigma rule `Detect Weaver E-cology File Read via XML-RPC` to identify exploitation attempts targeting the vulnerable XML-RPC endpoint.
*   Monitor web server logs for suspicious requests to the XmlRpcServlet endpoint, specifically those containing `WorkflowService.getAttachment` or `WorkflowService.LoadTemplateProp`, using the provided Sigma rule.
*   Implement network segmentation to limit the blast radius of a potential compromise and restrict access to sensitive internal resources.
