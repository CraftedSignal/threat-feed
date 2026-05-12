---
title: CVE-2026-40357 - Microsoft SharePoint Deserialization Vulnerability
slug: 2026-05-sharepoint-deserialization
description: CVE-2026-40357 is a deserialization of untrusted data vulnerability in Microsoft Office SharePoint that allows an authorized attacker to execute code over a network.
date: "2026-05-12T18:33:48Z"
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
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40357
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40357
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40357
rules:
  - title: Detect CVE-2026-40357 Exploitation - Suspicious PowerShell Activity
    description: Detects CVE-2026-40357 exploitation — Monitors for unusual PowerShell activity, specifically suspicious commands, following successful authentication, indicative of potential post-exploitation behavior on a compromised SharePoint server.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-40357 Exploitation - SharePoint Process Spawning CMD
    description: Detects CVE-2026-40357 exploitation — Detects cmd.exe being spawned by SharePoint processes (w3wp.exe), which can indicate code execution via deserialization.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-40357 is a critical vulnerability affecting Microsoft Office SharePoint. The vulnerability stems from the insecure deserialization of untrusted data, potentially enabling an authenticated attacker with network access to execute arbitrary code on the target system. This vulnerability was published on May 12, 2026. Successful exploitation could lead to complete compromise of the SharePoint server, allowing the attacker to steal sensitive data, disrupt services, or establish a persistent foothold within the organization's network. Given the widespread use of SharePoint in enterprise environments, this vulnerability poses a significant risk.

## Attack Chain

1.  An authorized attacker gains initial access to the SharePoint environment, potentially through compromised credentials or other existing vulnerabilities.
2.  The attacker crafts a malicious payload containing serialized data designed to execute arbitrary code upon deserialization.
3.  The attacker uploads or injects the malicious payload into a SharePoint component that is vulnerable to deserialization. This could involve exploiting a feature that processes user-supplied data.
4.  SharePoint attempts to deserialize the untrusted data.
5.  During deserialization, the malicious payload triggers the execution of arbitrary code.
6.  The attacker gains control of the SharePoint server process.
7.  The attacker uses the compromised SharePoint server to move laterally within the network, escalating privileges and accessing sensitive data.
8. The attacker achieves their final objective, which could include data exfiltration, deploying ransomware, or establishing a persistent backdoor for future access.

## Impact

Successful exploitation of CVE-2026-40357 can lead to complete compromise of the Microsoft Office SharePoint server. An attacker can execute arbitrary code, potentially leading to data breaches, service disruption, or the establishment of a persistent foothold in the organization's network. The impact is significant due to SharePoint's central role in document management and collaboration within many organizations.

## Recommendation

*   Apply the security updates released by Microsoft to address CVE-2026-40357 on all affected Office SharePoint installations to remediate the deserialization vulnerability.
*   Implement network segmentation to limit the blast radius of a potential compromise.
*   Deploy the Sigma rule "Detect CVE-2026-40357 Exploitation - Suspicious PowerShell Activity" to identify potential exploitation attempts based on unusual PowerShell activity post-authentication.
*   Monitor SharePoint logs for unusual activity related to deserialization processes.
