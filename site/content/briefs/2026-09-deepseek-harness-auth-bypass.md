---
title: Authentication Bypass in DeepSeek Harness via Host Header Spoofing
slug: 2026-09-deepseek-harness-auth-bypass
description: DeepSeek Harness versions prior to 0.1.2-alpha.1 contain an authentication bypass vulnerability allowing unauthorized remote control of the agent via a spoofed HTTP Host header.
date: "2026-09-08T17:42:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:deepseek:harness:*:*:*:*:*:*:*:*
vendors:
  - DeepSeek
products:
  - Harness (< 0.1.2-alpha.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: DeepSeek Harness before 0.1.2-alpha.1 contains an authentication bypass vulnerability in its local HTTP control-plane API that allows attackers to gain full agent control by supplying a spoofed Host header.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can exploit this flaw to invoke privileged commands such as commands/execute with danger-full-access permissions.
    confidence_band: high
cves:
  - id: CVE-2026-82533
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82533
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade DeepSeek Harness to version 0.1.2-alpha.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies version 0.1.2-alpha.1 as the fix
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the Harness control-plane API
      owner: Network Security
      addresses: CVE-2026-82533
      evidence: Vulnerability allows remote command execution via local API
---

DeepSeek Harness versions prior to 0.1.2-alpha.1 are affected by a critical authentication bypass vulnerability located in the local HTTP control-plane API. The vulnerability exists because the API server relies on the client-provided HTTP Host header for security validation instead of verifying the actual TCP connection origin. This flaw permits an attacker to spoof the Host header, effectively bypassing all authentication mechanisms. Upon successful exploitation, an attacker can obtain full control over the agent, execute privileged commands, modify session approval policies to achieve unconfined execution, and exfiltrate all stored conversation history without the need for credentials or API keys. Defenders must prioritize upgrading to version 0.1.2-alpha.1 or later to remediate this control-plane exposure.

## Impact

Successful exploitation of CVE-2026-82533 results in total loss of confidentiality and integrity of the DeepSeek Harness agent. Unauthorized actors can exfiltrate sensitive conversation data and execute arbitrary commands with full agent privileges, leading to potential lateral movement if the agent has further access to internal infrastructure.

## Recommendation

Prioritize the following actions to secure environments using DeepSeek Harness:

- Upgrade all instances of DeepSeek Harness to version 0.1.2-alpha.1 or later immediately.
- Restrict access to the HTTP control-plane API via network segmentation or firewall rules, ensuring only authorized administrative IP addresses can reach the interface.
- Implement monitoring on the API to detect abnormal Host header values or unauthorized attempts to access the /commands/execute or session policy configuration endpoints.
