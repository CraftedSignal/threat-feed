---
brief_id: brief-2026-11-10-ag2-shell-injection
event_id: brief-2026-11-10-ag2-shell-injection
revision: 1
activity_at: "2026-11-10T16:37:20Z"
title: 'AG2: SandboxShellTool command injection (CVE-2026-113663)'
slug: 2026-11-ag2-shell-injection
description: The SandboxShellTool in AG2 and AutoGen fails to filter newline characters, allowing attackers to bypass command allowlists and read-only restrictions to execute arbitrary shell commands via CVE-2026-113663.
date: "2026-11-10T16:37:20Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ag2:ag2:*:*:*:*:*:*:*:*
  - cpe:2.3:a:autogen:autogen:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - vulnerability
  - agent-security
vendors:
  - AG2
products:
  - ag2 (>= 0.13.2, < 1.1.1)
  - autogen (>= 0.13.2, <= 0.14.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: A POSIX shell splits sh -c "<line1>\n<line2>" into two sequential statements, the same as if they were separated by ;.
    confidence_band: high
cves:
  - id: CVE-2026-113663
    cvss: 8.8
    epss: 0.00347
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-2h4w-29cv-2cmv
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch ag2 to 1.1.1 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability CVE-2026-113663 affects versions < 1.1.1 (ag2) and <= 0.14.1 (autogen).
  hunt_leads:
    - lead: Identify processes spawned by the agent framework containing newline characters in command-line arguments.
      technique_id: T1059.004
      data_needed:
        - Process creation logs (Event ID 1 or equivalent) capturing full CommandLine.
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The bypass relies on embedding \n in the string passed to sh -c.
  mitigation_plan:
    - priority: immediate
      action: Transition from LocalEnvironment() to containerized sandbox environments for all untrusted agent executions.
      owner: Detection Engineering
      addresses: CVE-2026-113663
      evidence: LocalEnvironment() runs commands directly on the host subprocess, resulting in no real isolation.
---

The `SandboxShellTool` within the AG2 and AutoGen frameworks contains a command injection vulnerability (CVE-2026-113663) due to insufficient input validation. The tool relies on a denylist of shell operators (e.g., `;`, `&&`, `|`) to enforce `allowed` command allowlists and `readonly=True` modes. Because newline characters (`\n`, `\r`) are not included in this denylist, an attacker can embed newlines to chain arbitrary commands. When the tool executes the input using `sh -c`, the shell treats the newline as a command separator, successfully executing subsequent malicious instructions. This issue is particularly critical when using the `LocalEnvironment()` backend, which executes commands directly on the host process without containerized isolation.

## Impact
Successful exploitation allows for full command execution on the host machine running the agent. This is reachable through indirect prompt injection where an LLM is coerced into providing a command string containing a newline, bypassing intended security boundaries of the sandbox tool.

## Recommendation
- Update `ag2` to version 1.1.1 or later.
- Update `autogen` to version 0.14.2 or later.
- For deployments currently unable to patch, ensure that agents using `SandboxShellTool` operate within strictly isolated environments (e.g., containerized sandboxes) rather than the default `LocalEnvironment()`.
- Review agent logs for shell commands containing unexpected newline characters if the underlying application telemetry captures raw tool inputs.
