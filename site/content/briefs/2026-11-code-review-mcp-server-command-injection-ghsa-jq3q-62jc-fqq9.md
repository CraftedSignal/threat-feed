---
brief_id: brief-2026-11-17-code-review-mcp-server-command-injection-ghsa-jq3q-62jc-fqq9
event_id: brief-2026-11-17-code-review-mcp-server-command-injection-ghsa-jq3q-62jc-fqq9
revision: 1
activity_at: "2026-11-17T03:32:45Z"
title: 'code-review-mcp-server: Command injection (CVE-2026-68934)'
slug: 2026-11-code-review-mcp-server-command-injection-ghsa-jq3q-62jc-fqq9
description: The code-review-mcp-server package prior to version 1.5.3 is vulnerable to command injection via unsanitized folderPath and baseBranch parameters, which are interpolated into shell commands executed by child_process.execSync.
date: "2026-11-17T03:32:45Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:orcus2021:code_review_mcp_server:*:*:*:*:*:*:*:*
tags:
  - command-injection
vendors:
  - Orcus2021
products:
  - code-review-mcp-server
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: caller-controlled folderPath and baseBranch string parameters that are interpolated into command strings executed by child_process.execSync through /bin/sh
    confidence_band: high
cves:
  - id: CVE-2026-68934
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-68934
  - https://github.com/advisories/GHSA-jq3q-62jc-fqq9
action_plan:
  hunt_leads:
    - lead: Search process execution logs for child processes spawned by the code-review-mcp-server process containing shell metacharacters such as ';', '$(', '`', or '|' in command-line arguments, specifically investigating processes triggered by git or gh tools.
      technique_id: T1059
      data_needed:
        - process_creation_events
        - parent_process_name
        - command_line_arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: caller-controlled folderPath and baseBranch string parameters that are interpolated into command strings executed by child_process.execSync through /bin/sh
---

## Overview
code-review-mcp-server, a tool for automating code reviews, is vulnerable to command injection in versions prior to 1.5.3. Several MCP tools - specifically getLocalGitDiff, codeReview, createPR, and getPRTemplate - accept caller-controlled folderPath and baseBranch string parameters. These parameters are interpolated into command strings executed by child_process.execSync through /bin/sh. 

## Attack Chain
An attacker providing crafted input containing shell metacharacters, command substitution, or quote-breaking sequences can force the execution of arbitrary commands. The commands run with the privileges of the host process executing the MCP server.

## Impact
Successful exploitation results in arbitrary command execution on the host system.

## Recommendation
Upgrade to code-review-mcp-server version 1.5.3 or later. This version replaces execSync calls with execFileSync using argument arrays, which prevents shell interpretation of user-provided inputs.
