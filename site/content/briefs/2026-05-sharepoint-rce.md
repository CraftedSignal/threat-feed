---
title: Microsoft SharePoint Remote Code Execution Vulnerability (CVE-2026-45659)
slug: 2026-05-sharepoint-rce
description: A remote code execution vulnerability, tracked as CVE-2026-45659, affects Microsoft SharePoint Enterprise Server 2016, SharePoint Server 2019, and SharePoint Server Subscription Edition, allowing an attacker to execute arbitrary code remotely.
date: "2026-05-22T13:05:32Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve-2026-45659
  - rce
  - sharepoint
  - remote code execution
  - vulnerability
vendors:
  - Microsoft
products:
  - SharePoint Enterprise Server 2016
  - SharePoint Server 2019
  - SharePoint Server Subscription Edition
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0634/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45659
  - https://www.cve.org/CVERecord?id=CVE-2026-45659
rules:
  - title: Detect CVE-2026-45659 Exploitation Attempt via HTTP Request
    description: Detects CVE-2026-45659 exploitation attempt via suspicious HTTP requests to SharePoint servers. This rule identifies requests containing specific patterns indicative of code injection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-45659 - Webshell Creation in SharePoint Directory
    description: Detects CVE-2026-45659 - Creation of suspicious files (e.g., ASPX webshells) within SharePoint directories, indicating potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A critical remote code execution (RCE) vulnerability, identified as CVE-2026-45659, has been discovered in Microsoft SharePoint products. This vulnerability affects SharePoint Enterprise Server 2016, SharePoint Server 2019, and SharePoint Server Subscription Edition. Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary code on the target system. The vulnerability was disclosed in a Microsoft Security Bulletin on May 21, 2026. It is crucial for organizations using affected versions of SharePoint to apply the necessary patches as soon as possible to mitigate the risk of exploitation. Given the widespread use of SharePoint in enterprise environments, this vulnerability poses a significant threat.

## Attack Chain

1.  An unauthenticated attacker sends a specially crafted request to a vulnerable SharePoint server.
2.  The request exploits a flaw in the way SharePoint processes specific types of data.
3.  This leads to the execution of arbitrary code within the context of the SharePoint application pool.
4.  The attacker gains control over the SharePoint server.
5.  The attacker leverages the initial access to move laterally within the network.
6.  The attacker compromises other systems and resources within the organization's environment.
7.  The attacker installs a webshell for persistent access.
8.  The final objective is to exfiltrate sensitive data or deploy ransomware.

## Impact

Successful exploitation of CVE-2026-45659 can lead to complete compromise of the SharePoint server and potentially the entire network. An attacker can gain unauthorized access to sensitive data, disrupt services, or deploy malicious payloads like ransomware. Given the widespread use of SharePoint for document management and collaboration, this vulnerability poses a significant risk to organizations across various sectors. If exploited, this vulnerability allows remote code execution, potentially leading to data breaches, system downtime, and financial losses.

## Recommendation

*   Apply the patches provided in the Microsoft Security Bulletin CVE-2026-45659 to remediate the remote code execution vulnerability on all affected SharePoint servers.
*   Deploy the Sigma rule `Detect CVE-2026-45659 Exploitation Attempt via HTTP Request` to detect potential exploitation attempts.
*   Monitor web server logs for suspicious HTTP requests targeting SharePoint servers as described in the Attack Chain.
*   Implement network segmentation to limit the potential impact of a successful exploitation as mentioned in the attack chain, specifically lateral movement.
