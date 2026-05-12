---
title: 'CVE-2026-35439: Microsoft Office SharePoint Deserialization Vulnerability'
slug: 2026-05-sharepoint-deserialization
description: CVE-2026-35439 is a deserialization of untrusted data vulnerability in Microsoft Office SharePoint that allows an authorized attacker to execute code over a network, potentially leading to remote code execution.
date: "2026-05-12T18:33:31Z"
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
    technique_id: T1219
    technique_name: Remote Services
cves:
  - id: CVE-2026-35439
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35439
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35439
rules:
  - title: Detects CVE-2026-35439 Exploitation Attempts — Suspicious HTTP Request to SharePoint with Serialized Data
    description: Detects CVE-2026-35439 exploitation attempts — HTTP POST requests to SharePoint endpoints with potential serialized payloads in the request body.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
  - title: Detects CVE-2026-35439 Exploitation Attempts — SharePoint File Upload with Suspicious Extension
    description: Detects CVE-2026-35439 exploitation attempts — file uploads to SharePoint with extensions commonly associated with serialized objects.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-35439 is a critical vulnerability affecting Microsoft Office SharePoint, stemming from the deserialization of untrusted data. An authorized attacker, with network access, can exploit this flaw to execute arbitrary code on the target system. This vulnerability poses a significant risk, potentially allowing attackers to gain control of SharePoint servers, leading to data breaches, service disruption, or further lateral movement within the network. The vulnerability was published on May 12, 2026. Exploitation of this vulnerability requires an attacker to have authorization on the SharePoint instance.

## Attack Chain

1.  Attacker gains authorized access to the SharePoint environment. This could be through compromised credentials or other valid access methods.
2.  The attacker crafts a malicious payload containing serialized data designed to execute arbitrary code when deserialized.
3.  The attacker injects the malicious serialized data into a SharePoint component that is vulnerable to deserialization. This may involve uploading a specially crafted file, sending a malicious API request, or modifying existing data within SharePoint.
4.  SharePoint processes the injected data, triggering the deserialization vulnerability.
5.  The vulnerable deserialization routine executes the attacker-controlled code within the context of the SharePoint application.
6.  The attacker gains remote code execution on the SharePoint server.
7.  The attacker leverages the compromised SharePoint server for further malicious activities, such as data exfiltration, lateral movement within the network, or denial-of-service attacks.

## Impact

Successful exploitation of CVE-2026-35439 can lead to complete compromise of the SharePoint server and potentially the entire SharePoint farm. This could result in the loss of sensitive data, disruption of business operations, and reputational damage. Given the widespread use of SharePoint in organizations for document management and collaboration, the impact could be significant, affecting numerous users and departments. The vulnerability has a CVSS v3.1 base score of 8.8, indicating a high level of severity.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-35439 on all affected SharePoint servers immediately. Reference: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35439>
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts targeting this vulnerability.
*   Review SharePoint access controls and implement the principle of least privilege to minimize the potential impact of compromised credentials (TTPs: TA0001).
*   Monitor SharePoint logs for suspicious activity related to deserialization vulnerabilities (logsource: webserver, file_event).
