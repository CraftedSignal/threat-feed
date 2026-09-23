---
title: Arbitrary Code Execution Vulnerability in GNU Wget
slug: 2026-09-wget-rce
description: A local vulnerability in GNU Wget, identified as CVE-2024-38428, allows an attacker to achieve arbitrary code execution through the processing of malformed input strings.
date: "2026-09-23T13:59:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gnu:wget:*:*:*:*:*:*:*:*
vendors:
  - GNU
products:
  - wget (CVE-2024-38428)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A local attacker can exploit a vulnerability in wget to execute arbitrary program code.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in wget allows a local attacker to execute arbitrary program code, potentially leading to privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2024-38428
    cvss: 9.1
    epss: 0.00672
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3518
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all systems running GNU Wget to assess exposure to CVE-2024-38428.
      owner: IT Operations
      due: 48h
      evidence: Source confirms vulnerability in wget.
  mitigation_plan:
    - priority: immediate
      action: Update GNU Wget to the latest patched version.
      owner: IT Operations
      addresses: CVE-2024-38428
      evidence: Standard patching procedure for RCE vulnerabilities.
---

GNU Wget contains a security vulnerability that permits a local attacker to execute arbitrary code. The flaw is triggered by improper handling of specific input strings during the file retrieval process. By tricking a local user into executing a crafted command involving a malicious URL or file path, an attacker can cause the application to process inputs in a way that leads to unauthorized code execution. Depending on the privileges of the user executing the command, this may facilitate privilege escalation within the affected system. This impact is significant for environments where users rely on Wget for automated task scripting or frequent command-line file downloads.

## Impact

Successful exploitation allows a local attacker to gain the same execution context as the user running the Wget utility. In scenarios where Wget is executed by privileged users or automated system services, this vulnerability can lead to full system compromise or persistence, significantly impacting the integrity and security of the affected workstation or server.

## Recommendation

Prioritize the identification and patching of all instances of GNU Wget to the version containing the fix for CVE-2024-38428. Monitor system logs for unusual command-line arguments passed to wget, particularly those involving long or encoded strings that may indicate attempts to exploit buffer overflows or parsing logic errors.
