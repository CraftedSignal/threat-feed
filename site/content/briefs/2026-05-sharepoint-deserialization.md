---
title: CVE-2026-33112 - Microsoft SharePoint Deserialization Vulnerability
slug: 2026-05-sharepoint-deserialization
description: CVE-2026-33112 is a deserialization of untrusted data vulnerability in Microsoft Office SharePoint that allows an authorized attacker to execute code over a network.
date: "2026-05-12T18:18:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - deserialization
  - rce
  - sharepoint
vendors:
  - Microsoft
products:
  - Office SharePoint
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-33112
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33112
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33112
rules:
  - title: Detect CVE-2026-33112 Exploitation Attempt via Suspicious HTTP Request
    description: Detects CVE-2026-33112 exploitation attempt via suspicious HTTP POST request patterns indicative of deserialization attacks
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detect CVE-2026-33112 Exploitation Attempt via Suspicious User-Agent
    description: Detects CVE-2026-33112 exploitation attempt via unusual User-Agent strings
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-33112 is a critical vulnerability affecting Microsoft Office SharePoint. This deserialization of untrusted data vulnerability enables an authorized attacker to execute arbitrary code remotely over a network. Successful exploitation could lead to complete system compromise, data breaches, or denial of service. Given the widespread use of SharePoint within organizations, this vulnerability poses a significant risk and requires immediate attention from security teams. The vulnerability was published on 2026-05-12 and is documented by Microsoft.

## Attack Chain

1.  Attacker authenticates to a vulnerable SharePoint instance with valid credentials.
2.  Attacker crafts a malicious payload containing serialized, untrusted data.
3.  The attacker sends the crafted payload to a SharePoint endpoint that processes deserialization.
4.  SharePoint attempts to deserialize the untrusted data without proper validation.
5.  The deserialization process triggers the execution of malicious code embedded within the payload.
6.  The attacker gains code execution within the context of the SharePoint application pool.
7.  The attacker pivots to other systems on the network.
8.  The attacker achieves complete control over the SharePoint server.

## Impact

Successful exploitation of CVE-2026-33112 allows an authorized attacker to execute arbitrary code on the SharePoint server. This could lead to complete system compromise, data exfiltration, or denial of service. Given the central role SharePoint often plays in document management and collaboration, a successful attack can have significant impact, including potential compromise of sensitive data.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-33112 as soon as possible by referencing the advisory at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33112.
*   Deploy the Sigma rule "Detect CVE-2026-33112 Exploitation Attempt via Suspicious HTTP Request" to monitor for potential exploitation attempts in web server logs.
*   Monitor network traffic for unusual patterns or connections originating from SharePoint servers that might indicate post-exploitation activity.
