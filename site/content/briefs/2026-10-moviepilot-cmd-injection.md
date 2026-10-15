---
title: Command Injection in MoviePilot
slug: 2026-10-moviepilot-cmd-injection
description: MoviePilot versions through 3.1.5 are vulnerable to command injection via the ExecuteCommandTool, allowing unauthenticated or low-privileged actors to achieve remote code execution.
date: "2026-10-15T02:34:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:moviepilot:moviepilot:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - command-injection
  - cve-2026-77931
vendors:
  - MoviePilot
products:
  - MoviePilot (<= 3.1.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can craft content that instructs the model to invoke execute_command with confirm_dangerous set to true, bypassing the validate_command_safety denylist.
    confidence_band: high
cves:
  - id: CVE-2026-77931
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77931
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all instances of MoviePilot to a version beyond 3.1.5
      owner: IT Operations
      due: 48h
      evidence: Source advisory confirms vulnerability in versions through 3.1.5
  mitigation_plan:
    - priority: immediate
      action: Upgrade MoviePilot to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-77931
      evidence: NVD advisory for CVE-2026-77931
---

MoviePilot through version 3.1.5 contains a critical command injection vulnerability. The flaw exists within the application's handling of untrusted content, specifically during tasks involving web browsing, searching, or parsing torrent metadata. The application utilizes a tool named ExecuteCommandTool, which passes inputs to the `asyncio.create_subprocess_shell` function in Python. Attackers can embed malicious instructions within untrusted data that trick the system into invoking this tool. Furthermore, the vulnerability includes a logic flaw in the command safety validation mechanism, where an attacker can set `confirm_dangerous` to true to bypass the denylist. If the application is running in an environment with an active admin session, the attacker can leverage the `is_admin` context to execute arbitrary OS commands on the host machine. This poses a significant risk to the integrity and confidentiality of the host environment.

## Impact

Successful exploitation allows for arbitrary code execution with the privileges of the MoviePilot service process. This can lead to full system compromise, data exfiltration, and lateral movement within the network. This vulnerability affects all MoviePilot deployments running version 3.1.5 or earlier.

## Recommendation

1. Patch all instances of MoviePilot by upgrading to the latest version that remediates CVE-2026-77931.
2. Implement strict network egress filtering for the container or server running MoviePilot to prevent reverse shell callbacks.
3. Ensure the MoviePilot service runs with the least privilege necessary, specifically avoiding execution as the root user.
4. Audit logs for anomalous subprocess execution patterns, particularly those originating from the MoviePilot process tree involving `sh` or `bash`.
