---
title: Sudo Policy Bypass via execveat System Call
slug: 2026-08-sudo-policy-bypass
description: Sudo versions through 1.9.17p2 are vulnerable to a privilege escalation flaw where the ptrace-based intercept mode fails to filter execveat system calls, allowing unauthorized command execution.
date: "2026-08-29T17:41:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sudo_project:sudo:*:*:*:*:*:*:*:*
vendors:
  - Sudo
products:
  - Sudo (<= 1.9.17p2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Users permitted to run specific commands can execute denied programs by calling execveat directly or through fexecve, bypassing policy enforcement and logging.
    confidence_band: high
cves:
  - id: CVE-2026-82474
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82474
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Sudo to 1.9.17p3 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-82474 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade Sudo to 1.9.17p3
      owner: IT Operations
      addresses: CVE-2026-82474
      evidence: NVD vulnerability report
---

Sudo versions up to and including 1.9.17p2 contain a security vulnerability (CVE-2026-82474) in the ptrace-based intercept mode. This feature, designed to enforce fine-grained policy restrictions on commands, fails to apply those policy checks to the `execveat` system call. Consequently, a user who is granted sudo privileges for specific commands can bypass these restrictions to execute arbitrary programs that were intended to be blocked. The vulnerability is triggered by directly invoking `execveat` or the `fexecve` function. This flaw undermines the security integrity of sudo-restricted environments, as it allows attackers to execute denied programs while simultaneously bypassing audit logging mechanisms associated with policy enforcement. This vulnerability is highly relevant to organizations relying on sudo intercept mode for privilege limitation and command auditing.

## Impact

Successful exploitation allows local users to escalate their privileges by executing unauthorized commands that would otherwise be blocked by sudo policies. This impacts security posture by enabling lateral movement, persistence, or unauthorized system changes within the context of the elevated sudo session. Given the widespread use of sudo across Linux-based infrastructure, the potential for unauthorized code execution in restricted environments is high.

## Recommendation

- Upgrade the Sudo package to version 1.9.17p3 or later to remediate CVE-2026-82474.
- Audit existing sudoers configurations to identify environments where ptrace-based intercept mode is enabled.
- Monitor system audit logs for anomalous `execveat` system call activity originating from users with restricted sudo access.
