---
brief_id: brief-2026-10-27-atxp-gemini-cli-rce
event_id: brief-2026-10-27-atxp-gemini-cli-rce
revision: 1
activity_at: "2026-10-27T15:50:10Z"
title: 'ATXP Gemini CLI extension: OS command injection via MCP (CVE-2026-117560)'
slug: 2026-10-atxp-gemini-cli-rce
description: The ATXP Gemini CLI extension through version 1.0.0 is vulnerable to OS command injection in the runAtxp() function due to unsanitized MCP tool parameters, allowing arbitrary code execution.
date: "2026-10-27T15:50:10Z"
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
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:atxp:gemini_cli_extension:*:*:*:*:*:*:*:*
vendors:
  - ATXP
products:
  - Gemini CLI extension (<= 1.0.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: Attackers can plant instructions in email or SMS content to inject $() or backtick substitutions into parameters like message_id, subject, or query, running commands as the user.
    confidence_band: high
cves:
  - id: CVE-2026-117560
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117560
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify and upgrade vulnerable ATXP Gemini CLI extension installations to a version > 1.0.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-117560
  hunt_leads:
    - lead: Identify suspicious shell process spawns originating from the Gemini CLI process
      technique_id: T1059.004
      data_needed:
        - Process creation logs (Event ID 1 or Auditd)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows execution of shell commands through unsanitized MCP tool parameters
  mitigation_plan:
    - priority: immediate
      action: Upgrade ATXP Gemini CLI extension to version > 1.0.0
      owner: IT Operations
      addresses: CVE-2026-117560
      evidence: CVE-2026-117560 vulnerability report
---

The ATXP Gemini CLI extension version 1.0.0 and earlier contains an OS command injection vulnerability within the runAtxp() function. The vulnerability is triggered when the extension processes unsanitized input via Model Context Protocol (MCP) tool parameters, specifically targeting the message_id, subject, or query fields. An attacker can supply shell substitution characters, such as $() or backticks, within email or SMS content to force the extension to execute arbitrary commands under the context of the user running the CLI tool.

## Impact
Successful exploitation allows an attacker to execute arbitrary shell commands with the privileges of the local user running the Gemini CLI extension, potentially leading to unauthorized data access, system modification, or persistence.

## Recommendation
- Upgrade the ATXP Gemini CLI extension to a patched version beyond 1.0.0 immediately.
- Audit the use of MCP tools and restrict the processing of untrusted input content (email/SMS) if the extension cannot be updated.
- Implement monitoring for suspicious child processes spawned by the Gemini CLI tool.
