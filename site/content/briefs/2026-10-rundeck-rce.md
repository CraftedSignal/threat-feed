---
title: OS Command Injection in Rundeck via CLIUtils
slug: 2026-10-rundeck-rce
description: Authenticated users can execute arbitrary OS commands on Windows nodes in Rundeck versions prior to 6.2.0 by injecting shell metacharacters into job options.
date: "2026-10-07T12:37:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pagerduty:rundeck:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - command-injection
  - vulnerability
vendors:
  - PagerDuty
products:
  - Rundeck (< 6.2.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: Attackers can inject cmd.exe metacharacters such as && or | into free-text options... running commands with node executor credential privileges.
    confidence_band: high
cves:
  - id: CVE-2026-106056
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106056
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Rundeck to 6.2.0 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Upgrade Rundeck to 6.2.0
      owner: IT Operations
      addresses: CVE-2026-106056
      evidence: Source advisory
---

Rundeck versions prior to 6.2.0 are vulnerable to an OS command injection flaw (CVE-2026-106056) affecting the CLIUtils.quoteWindowsCMDArg utility. This vulnerability allows an authenticated user who possesses job execution permissions to manipulate command-line arguments during job execution on Windows-based nodes. By providing crafted input within free-text job options containing shell metacharacters such as ampersands (&&) or pipes (|), an attacker can bypass the intended quoting mechanism. Because the utility wraps inputs in single quotes that are ineffective against these specific Windows shell metacharacters, the injected commands are executed by the node executor with its associated privileges. This flaw represents a significant risk for environments where internal users have access to job orchestration but are not intended to have full command-line access to the underlying infrastructure nodes.

## Impact

Successful exploitation allows authenticated users to achieve arbitrary command execution on target Windows nodes. This can lead to full compromise of the affected nodes, privilege escalation within the context of the node executor, and potential lateral movement across the infrastructure managed by the compromised Rundeck instance. The scope of impact is limited to environments utilizing Rundeck to manage Windows-based systems where job options are not strictly validated.

## Recommendation

1. Upgrade Rundeck to version 6.2.0 or later immediately to resolve the vulnerability in CLIUtils.quoteWindowsCMDArg.
2. Implement strict input validation for all free-text job options within Rundeck configurations to ensure they do not contain shell metacharacters.
3. Review the principle of least privilege for accounts assigned job run permissions in Rundeck to minimize the impact of potential command injection attempts.
4. Monitor process execution logs on Windows nodes managed by Rundeck for suspicious child processes spawned by the node executor account.
