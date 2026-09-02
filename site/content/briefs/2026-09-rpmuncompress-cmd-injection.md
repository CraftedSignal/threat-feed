---
title: Command Injection Vulnerability in rpmuncompress
slug: 2026-09-rpmuncompress-cmd-injection
description: A command injection vulnerability in rpmuncompress allows local attackers to execute arbitrary code by supplying specially crafted archive filenames containing shell metacharacters.
date: "2026-09-02T17:16:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rpm:rpmuncompress:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - command-injection
  - linux
vendors:
  - rpm
products:
  - rpmuncompress
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This command injection vulnerability allows a local attacker to execute arbitrary commands.
    confidence_band: high
cves:
  - id: CVE-2026-84838
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84838
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory systems where rpmuncompress is installed or used in scripts.
      owner: IT Operations
      due: 48h
      evidence: Source document identifies rpmuncompress as the vulnerable product.
  hunt_leads:
    - lead: Search logs for command line executions containing 'rpmuncompress' alongside shell metacharacters.
      technique_id: T1059.004
      data_needed:
        - Process creation logs (Linux auditd/Sysmon for Linux)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability requires malicious filenames with shell metacharacters to trigger.
  mitigation_plan:
    - priority: immediate
      action: Restrict execute permissions for rpmuncompress to authorized users only.
      owner: IT Operations
      addresses: CVE-2026-84838
      evidence: Source identifies local command injection vulnerability.
---

CVE-2026-84838 is a command injection vulnerability residing within the rpmuncompress utility. The flaw exists due to improper sanitization of archive filenames, which allows an attacker to inject arbitrary shell metacharacters into the command execution flow. When a user or an automated script processes a malicious archive file using rpmuncompress, the unescaped filename is passed directly to the underlying shell command string. This leads to the execution of attacker-supplied commands with the privileges of the user running the utility. Defenders should be aware that this vulnerability facilitates local privilege escalation or arbitrary code execution, impacting the confidentiality, integrity, and availability of data accessible by the affected process.

## Impact

Successful exploitation of CVE-2026-84838 allows a local attacker to execute arbitrary commands, potentially resulting in full system compromise for the specific user context in which rpmuncompress is invoked. Automated workflows that process externally sourced archive files are at higher risk.

## Recommendation

- Monitor for the execution of rpmuncompress on systems processing external or untrusted archive files.
- Implement input validation on filenames before passing them to archive extraction utilities in automated workflows.
- Audit logs for instances where rpmuncompress is invoked with filenames containing shell metacharacters like semicolon (;), pipe (|), or backticks (`).
