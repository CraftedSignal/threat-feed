---
title: Unrestricted File Upload in SourceCodester Contact Tracing System
slug: 2026-10-sourcecodester-rce
description: SourceCodester Contact Tracing System 1.0 is vulnerable to an unrestricted file upload flaw in the /classes/Users.php component, allowing remote attackers to achieve arbitrary file uploads.
date: "2026-10-13T08:33:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:contact_tracing_system:1.0:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - remote-code-execution
  - file-upload
  - sourcecodester
vendors:
  - SourceCodester
products:
  - Contact Tracing System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely via the /classes/Users.php?f=save endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This manipulation of the argument img/id causes unrestricted upload, potentially leading to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-108973
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108973
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit web server logs for HTTP POST requests to /classes/Users.php where the query parameter contains 'f=save'.
      owner: SOC
      due: 24h
      evidence: Source document identifies /classes/Users.php?f=save as the attack vector.
  mitigation_plan:
    - priority: immediate
      action: Decommission or isolate vulnerable SourceCodester Contact Tracing System 1.0 instances.
      owner: IT Operations
      addresses: CVE-2026-108973
      evidence: NVD report confirms vulnerability in 1.0.
---

SourceCodester Contact Tracing System version 1.0 contains a critical security vulnerability related to unrestricted file uploads. The issue resides within the move_uploaded_file function located in the file /classes/Users.php when processing the 'img' or 'id' parameters during the 'save' action. This vulnerability allows an unauthenticated remote attacker to bypass intended file type restrictions and upload arbitrary files - such as web shells or malicious scripts - directly to the application's server. Because the application handles user-supplied input without sufficient sanitization or validation, this flaw can be leveraged to achieve remote code execution (RCE) on the underlying host, posing a significant risk to systems running this software.

## Impact

Successful exploitation of this vulnerability permits unauthorized remote attackers to upload and execute arbitrary code on the server hosting the Contact Tracing System. This could lead to a full system compromise, exfiltration of sensitive contact tracing data, or further lateral movement within the network. The exploit has been publicly disclosed, increasing the likelihood of opportunistic exploitation attempts against internet-facing instances of this legacy or unpatched system.

## Recommendation

1. Inventory all instances of the SourceCodester Contact Tracing System within the environment to identify systems running version 1.0.
2. Restrict access to the /classes/Users.php endpoint using network-level controls if immediate patching or decommissioning is not feasible.
3. Implement egress filtering on the web server to prevent it from initiating outbound connections (reverse shells) following a successful exploit.
4. Perform forensic analysis on the web server directory to detect unknown or unauthorized file uploads, particularly those with executable extensions.
