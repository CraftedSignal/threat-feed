---
brief_id: brief-2026-11-03-nnn-command-injection
event_id: brief-2026-11-03-nnn-command-injection
revision: 1
activity_at: "2026-11-03T20:01:27Z"
title: 'Jarun nnn: OS command injection via togglex plugin (CVE-2026-121548)'
slug: 2026-11-nnn-command-injection
description: The nnn file manager utility contains a command injection vulnerability in the togglex plugin, allowing attackers to execute arbitrary commands through maliciously crafted filenames.
date: "2026-11-03T20:01:27Z"
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
  - cpe:2.3:a:jarun:nnn:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - vulnerability
vendors:
  - Jarun
products:
  - nnn (<= 5.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: Attackers can place files whose names contain a double quote and shell syntax, which xargs -I splices into an sh -c script
    confidence_band: high
cves:
  - id: CVE-2026-121548
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121548
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and remove or disable the plugins/togglex script on affected Linux systems
      owner: IT Operations
      due: 48h
      evidence: nnn contains an OS command injection vulnerability in plugins/togglex
  hunt_leads:
    - lead: Hunt for suspicious file names in directories managed by nnn
      technique_id: T1059.004
      data_needed:
        - File system metadata (find command output)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can place files whose names contain a double quote and shell syntax
  mitigation_plan:
    - priority: immediate
      action: Remove plugins/togglex script from the nnn plugin directory
      owner: IT Operations
      addresses: CVE-2026-121548
      evidence: nnn through 5.3 contains an OS command injection vulnerability in plugins/togglex
---

The nnn file manager (versions up to and including 5.3) contains an OS command injection vulnerability in the `plugins/togglex` script. The vulnerability arises because filenames containing double quotes and shell metacharacters are improperly passed to an `sh -c` script via `xargs -I`. This allows an attacker to achieve arbitrary code execution under the privileges of the user running the `togglex` plugin.

## Impact

An attacker who can control file names within a directory managed or processed by the `togglex` plugin can execute arbitrary shell commands with the privileges of the user invoking the utility.

## Recommendation

- Upgrade to a patched version of nnn when available or remove the `plugins/togglex` script from the installation directory.
- Review directory contents in high-risk areas for filenames containing unusual shell metacharacters (e.g., `"`, `$`, `;`, `&`, `|`, `\`, `` ` ``).
- Restrict user permissions to write or modify files in directories processed by file management utilities.
