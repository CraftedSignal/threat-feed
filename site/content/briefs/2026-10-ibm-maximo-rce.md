---
title: Remote Code Execution in IBM Maximo AI Service
slug: 2026-10-ibm-maximo-rce
description: IBM Maximo AI Service versions 9.1.0 and 9.2.0 are vulnerable to remote code execution due to improper control of code generation, allowing unauthenticated attackers to execute arbitrary code.
date: "2026-10-12T22:39:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ibm:maximo_ai_service:9.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:maximo_ai_service:9.2.0:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Maximo AI Service (9.1.0, 9.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM Maximo AI Service 9.1.0, and 9.2.0 could allow a remote attacker to execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: IBM Maximo AI Service 9.1.0, and 9.2.0 could allow a remote attacker to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-90920
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90920
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch IBM Maximo AI Service to the version recommended by IBM addressing CVE-2026-90920.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-90920 base score 9.8
  mitigation_plan:
    - priority: immediate
      action: Patch IBM Maximo AI Service to the latest available version.
      owner: IT Operations
      addresses: CVE-2026-90920
      evidence: CVE-2026-90920
---

IBM Maximo AI Service, specifically versions 9.1.0 and 9.2.0, contains a critical vulnerability identified as CVE-2026-90920. The flaw arises from improper control of code generation within the application, which may allow an unauthenticated remote attacker to execute arbitrary code. This vulnerability carries a CVSS v3.1 base score of 9.8, reflecting the high risk to organizational security. Given the nature of the AI service, successful exploitation could lead to full system compromise, data exfiltration, or the deployment of persistent malicious payloads within the Maximo environment. Defenders should prioritize patching affected instances to the latest secure version provided by IBM to mitigate the risk of unauthorized access and remote execution.

## Impact

Successful exploitation of CVE-2026-90920 allows unauthenticated remote attackers to execute arbitrary code on the affected server. This can result in complete system compromise, unauthorized access to sensitive maintenance and operational data, and potential lateral movement within the network. The vulnerability poses a significant risk to industrial and enterprise environments relying on IBM Maximo for asset and work management.

## Recommendation

- Identify all instances of IBM Maximo AI Service within the environment.
- Review IBM security bulletins for the latest firmware or patch release addressing CVE-2026-90920 and apply updates immediately.
- Isolate internet-facing instances of the affected service if immediate patching is not possible.
- Review web access logs for anomalous POST requests or unusual patterns targeting the Maximo AI service endpoints until a patch is applied.
