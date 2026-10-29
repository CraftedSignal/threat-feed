---
brief_id: brief-2026-10-29-systeminformation-command-injection
event_id: brief-2026-10-29-systeminformation-command-injection
revision: 1
activity_at: "2026-10-29T00:11:46Z"
title: 'systeminformation: Windows command injection via services() (CVE-2026-116576)'
slug: 2026-10-systeminformation-command-injection
description: The systeminformation Node.js package contains a command injection vulnerability in its services() function on Windows caused by insufficient sanitization of Unicode curly quotation marks.
date: "2026-10-29T00:11:46Z"
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
  validation_status: Source documented PoC verified against provided version
cpes:
  - cpe:2.3:a:systeminformation_project:systeminformation:*:*:*:*:*:node.js:*:*
tags:
  - command-injection
  - nodejs
  - library-vulnerability
products:
  - systeminformation (< 5.33.16)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.001
    subtechnique_name: PowerShell
    evidence: The expression runs with the permissions of the Node.js process.
    confidence_band: high
cves:
  - id: CVE-2026-116576
    cvss: 7.8
    epss: 0.00145
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-3f7j-7jwc-fxfj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116576
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade systeminformation dependency to >= 5.33.16
      owner: IT Operations
      due: 48h
      evidence: Vulnerability fixed in version 5.33.16
  hunt_leads:
    - lead: Identify Node.js applications invoking systeminformation.services() with suspicious characters
      technique_id: T1059.001
      data_needed:
        - Application logs or source code analysis
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The sanitizer in lib/util.js removes the ASCII double quote, but it does not remove U+201C or U+201D
  mitigation_plan:
    - priority: immediate
      action: Upgrade package to 5.33.16
      owner: IT Operations
      addresses: CVE-2026-116576
      evidence: Vendor advisory confirmation
---

The systeminformation package version 5.33.15 and below contains a command injection vulnerability on Windows within the `services()` function. The internal `sanitizeShellString()` utility fails to strip Unicode left and right curly quotation marks (U+201C and U+201D). Because these characters are interpreted as string delimiters by PowerShell, an attacker can supply a specially crafted service name to terminate the intended `Get-CimInstance` filter string and inject arbitrary PowerShell commands. These commands execute with the privileges of the hosting Node.js process.

## Impact

Successful exploitation allows arbitrary command execution on the host operating system. The scope of impact is limited to the privileges of the Node.js process, which may include access to files, sensitive environment variables, or other application resources. Remote exploitability is dependent on whether a consuming application passes attacker-controlled input directly to the `services()` function.

## Recommendation

- Upgrade the `systeminformation` package to version 5.33.16 or later.
- Review applications using `systeminformation` to identify if any user-supplied data is passed as arguments to the `services()` function.
- Apply input validation/sanitization to any data before passing it to library functions, treating `services()` inputs as untrusted content.
