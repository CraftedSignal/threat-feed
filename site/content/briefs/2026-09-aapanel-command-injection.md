---
title: Command Injection in aaPanel BaoTa via File Merge Handler
slug: 2026-09-aapanel-command-injection
description: An unauthenticated remote command injection vulnerability in the aaPanel BaoTa File Merge Handler allows attackers to execute arbitrary system commands via the split_file_path parameter.
date: "2026-09-28T08:49:19Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:aapanel:baota:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - rce
  - command-injection
vendors:
  - aaPanel
products:
  - BaoTa (<= 11.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can supply a malicious split_file_path argument to execute arbitrary system commands remotely.
    confidence_band: high
cves:
  - id: CVE-2026-101008
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101008
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block external access to the aaPanel administrative interface.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows remote command execution without authentication.
  mitigation_plan:
    - priority: immediate
      action: Implement WAF filter for shell metacharacters in split_file_path.
      owner: SOC
      addresses: CVE-2026-101008
      evidence: Source notes command injection via manipulation of split_file_path.
---

aaPanel BaoTa versions up to 11.8.0 contain a critical command injection vulnerability in the merge_split_file function, located within the file /www/server/panel/class/files.py. The vulnerability exists within the File Merge Handler component. An unauthenticated remote attacker can exploit this by sending a specially crafted request containing a malicious split_file_path argument. Because the application fails to properly sanitize this input before passing it to the underlying system shell, it allows for the execution of arbitrary commands with the privileges of the web application user. This flaw is publicly disclosed and currently lacks a vendor-provided patch. Defenders should treat this as a high-priority exposure, as public exploit code increases the likelihood of active exploitation.

## Impact

Successful exploitation results in full remote code execution on the target server. Given that aaPanel is a web hosting control panel, successful compromise typically yields administrative control over the underlying Linux OS and all hosted web content. This allows for data exfiltration, service disruption, and the potential use of the server as a pivot point within the infrastructure.

## Recommendation

1. Restrict external network access to the aaPanel management interface immediately, ensuring it is not reachable from the public internet.
2. Implement WAF rules to inspect HTTP requests for shell metacharacters (e.g., ;, |, &&, `) within the split_file_path parameter targeting the /www/server/panel/class/files.py file path.
3. Monitor system audit logs for unexpected processes spawned by the web server user (typically www or www-data).
4. Audit the server for evidence of post-exploitation activity, such as the creation of unauthorized web shells or persistence mechanisms.
