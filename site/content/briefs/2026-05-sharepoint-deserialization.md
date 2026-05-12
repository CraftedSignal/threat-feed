---
title: CVE-2026-40368 - Microsoft Office SharePoint Deserialization Vulnerability
slug: 2026-05-sharepoint-deserialization
description: CVE-2026-40368 is a deserialization of untrusted data vulnerability in Microsoft Office SharePoint, allowing an authorized attacker to execute code over a network.
date: "2026-05-12T18:43:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - deserialization
  - code-execution
  - sharepoint
vendors:
  - Microsoft
products:
  - Office SharePoint
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-40368
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40368
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40368
rules:
  - title: Detects CVE-2026-40368 Exploitation Attempt - SharePoint Suspicious Process Creation
    description: Detects CVE-2026-40368 exploitation attempt via process creation spawned by the SharePoint application pool.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1053.005
      - T1059.001
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-40368 Exploitation Attempt - SharePoint Suspicious File Modification
    description: Detects CVE-2026-40368 exploitation attempt via file modification in the SharePoint directory.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-40368 describes a deserialization vulnerability affecting Microsoft Office SharePoint. This vulnerability allows an authorized attacker to execute arbitrary code over a network by deserializing untrusted data. The vulnerability stems from how SharePoint handles incoming data streams, potentially allowing malicious code to be injected during the deserialization process. Successful exploitation could lead to complete system compromise. Defenders should prioritize patching vulnerable SharePoint instances to mitigate this risk.

## Attack Chain

1.  Attacker authenticates to a SharePoint instance with valid credentials.
2.  The attacker crafts a malicious payload containing serialized data designed to exploit the deserialization vulnerability.
3.  The attacker injects the malicious payload into a SharePoint component that processes serialized data, such as a web part or workflow.
4.  SharePoint attempts to deserialize the untrusted data without proper validation.
5.  The deserialization process executes the attacker's injected code.
6.  The attacker gains arbitrary code execution within the context of the SharePoint application pool account.
7.  The attacker can then escalate privileges, move laterally within the network, and compromise other systems.

## Impact

Successful exploitation of CVE-2026-40368 allows an attacker to execute arbitrary code on the affected Microsoft Office SharePoint server. The vulnerability has a CVSS v3.1 score of 8.0, indicating a high severity. This could lead to unauthorized access to sensitive data, modification of SharePoint content, or complete compromise of the server and potentially the entire network.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-40368 on all affected SharePoint servers (reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40368).
*   Monitor SharePoint logs for suspicious activity related to deserialization processes, looking for unusual patterns or error messages.
*   Implement strict input validation and sanitization measures to prevent the injection of malicious serialized data.
