---
title: 'CVE-2026-40365: Microsoft Office SharePoint Insufficient Access Control RCE'
slug: 2026-05-sharepoint-rce
description: CVE-2026-40365 is a vulnerability in Microsoft Office SharePoint that allows an authorized attacker to execute code over a network due to insufficient granularity of access control.
date: "2026-05-12T18:35:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - sharepoint
  - rce
vendors:
  - Microsoft
products:
  - Office SharePoint
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40365
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40365
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40365
rules:
  - title: Detects CVE-2026-40365 Exploitation Attempt — SharePoint Suspicious Process Creation
    description: Detects CVE-2026-40365 exploitation attempt through monitoring for suspicious process creation events originating from SharePoint processes.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-40365 Exploitation Attempt — SharePoint Suspicious Network Connection
    description: Detects CVE-2026-40365 exploitation attempt by monitoring for suspicious network connections from SharePoint processes to unusual ports or IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-40365 describes a vulnerability in Microsoft Office SharePoint that stems from insufficient granularity of access control. This flaw allows an authorized attacker to execute arbitrary code remotely over a network. Given the widespread use of SharePoint in enterprise environments, this vulnerability poses a significant risk. Successful exploitation could lead to unauthorized access to sensitive data, modification of critical systems, or disruption of business operations. Defenders should prioritize patching and consider implementing additional security measures to mitigate this threat.

## Attack Chain

1.  Attacker authenticates to a SharePoint instance with compromised or legitimate credentials.
2.  Attacker leverages their authorized access to target specific SharePoint components with insufficient access controls.
3.  Attacker crafts a malicious request to exploit the insufficient access control vulnerability.
4.  The malicious request bypasses intended security checks due to the granularity issue.
5.  The vulnerable SharePoint component processes the malicious request, leading to code execution.
6.  Attacker executes arbitrary code within the context of the SharePoint server.
7.  Attacker establishes persistence through techniques like creating scheduled tasks or modifying system files.
8.  Attacker pivots to other systems on the network to achieve broader objectives, such as data exfiltration or lateral movement.

## Impact

Successful exploitation of CVE-2026-40365 allows a remote attacker to execute arbitrary code on a vulnerable Microsoft Office SharePoint server. The impact includes potential compromise of sensitive data, disruption of services, and further exploitation of the internal network. Due to the insufficient granularity of access controls, an attacker with relatively low privileges could gain elevated privileges, leading to a full system compromise.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-40365 as soon as possible (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40365).
*   Monitor SharePoint servers for suspicious activity, such as unauthorized code execution or unexpected network connections.
*   Implement the Sigma rule provided to detect potential exploitation attempts.
