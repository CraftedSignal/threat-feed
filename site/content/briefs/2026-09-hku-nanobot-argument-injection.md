---
title: Remote Argument Injection in HKUDS nanobot
slug: 2026-09-hku-nanobot-argument-injection
description: HKUDS nanobot versions up to 0.2.1 contain an argument injection vulnerability in the ExecTool component that allows remote attackers to execute arbitrary commands.
date: "2026-09-14T19:36:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hkuds:nanobot:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - command-injection
vendors:
  - HKUDS
products:
  - nanobot (<= 0.2.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Such manipulation leads to argument injection.
    confidence_band: high
cves:
  - id: CVE-2026-90809
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90809
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Apply patch af582246f141311d574551b7571a517bcc3df750 to HKUDS nanobot
      owner: IT Operations
      addresses: CVE-2026-90809
      evidence: It is best practice to apply a patch to resolve this issue.
---

HKUDS nanobot versions up to 0.2.1 are vulnerable to remote argument injection within the ExecTool component. The flaw exists in the `ExecTool._guard_command` and `ExecTool._spawn` functions located in `nanobot/agent/tools/shell.py`. An attacker can manipulate arguments passed to these functions, leading to command injection on the host system. This vulnerability allows for remote execution, significantly impacting the confidentiality, integrity, and availability of the affected environment. Organizations utilizing versions 0.2.1 and earlier should apply patch `af582246f141311d574551b7571a517bcc3df750` immediately to mitigate potential exploitation.

## Impact

Successful exploitation of CVE-2026-90809 enables unauthenticated remote code execution, granting attackers the ability to execute arbitrary commands within the context of the nanobot agent. This could result in unauthorized system access, data exfiltration, or complete system compromise, depending on the privileges of the service account running the agent.

## Recommendation

- Upgrade HKUDS nanobot to a version containing the fix for CVE-2026-90809 by applying patch `af582246f141311d574551b7571a517bcc3df750`.
- Restrict access to the nanobot agent management interface to authorized networks and IP addresses.
- Review and audit the configuration of the `ExecTool` component to ensure command arguments are properly sanitized before processing.
