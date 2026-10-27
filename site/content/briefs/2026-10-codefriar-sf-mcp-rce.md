---
brief_id: brief-2026-10-27-codefriar-sf-mcp-rce
event_id: brief-2026-10-27-codefriar-sf-mcp-rce
revision: 1
activity_at: "2026-10-27T15:50:19Z"
title: 'Codefriar sf-mcp: OS command injection via Salesforce CLI flags (CVE-2026-117561)'
slug: 2026-10-codefriar-sf-mcp-rce
description: The sf-mcp package through version 1.3.2 is vulnerable to OS command injection due to insufficient sanitization of Salesforce CLI flag values in the escapeValue function, allowing remote code execution.
date: "2026-10-27T15:50:19Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation of MCP process behavior
cpes:
  - cpe:2.3:a:codefriar:sf-mcp:*:*:*:*:*:*:*:*
vendors:
  - Codefriar
products:
  - sf-mcp (<= 1.3.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Because escapeValue() in src/utils.ts fails to neutralize backticks, $() substitution, and other shell metacharacters, these values reach execSync in executeSfCommand and run as the MCP server user.
    confidence_band: high
cves:
  - id: CVE-2026-117561
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117561
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade sf-mcp to a version higher than 1.3.2.
      owner: IT Operations
      due: 48h
      evidence: Codefriar sf-mcp through 1.3.2 contains an OS command injection vulnerability
  hunt_leads:
    - lead: Identify MCP server processes spawning unexpected sub-processes or utilizing complex shell metacharacters in command-line arguments.
      technique_id: T1059.004
      data_needed:
        - Process creation logs (ParentProcessName, CommandLine, ProcessName)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: values reach execSync in executeSfCommand and run as the MCP server user
  mitigation_plan:
    - priority: immediate
      action: Upgrade sf-mcp to a version later than 1.3.2.
      owner: IT Operations
      addresses: CVE-2026-117561
      evidence: Codefriar sf-mcp through 1.3.2 contains an OS command injection vulnerability
---

Codefriar sf-mcp contains an OS command injection vulnerability in the `escapeValue()` function within `src/utils.ts`. The application fails to properly neutralize shell metacharacters, including backticks and `$()` substitution, when processing flags for the Salesforce CLI. These unsanitized values are subsequently passed to `execSync` in `executeSfCommand`, leading to arbitrary command execution as the user running the MCP server process.

## Impact

An attacker can execute arbitrary shell commands with the privileges of the user running the MCP server, potentially leading to unauthorized data access, system modification, or further lateral movement within the environment.

## Recommendation

* Update the `sf-mcp` package to a version beyond 1.3.2 to remediate the vulnerability in `src/utils.ts`.
* Review logs for the MCP server process for unexpected child processes or unusual command-line arguments involving Salesforce CLI flags.
* Audit environments running `sf-mcp` to ensure the process runs with the principle of least privilege, minimizing the impact of potential command execution.
