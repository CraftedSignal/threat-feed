---
brief_id: brief-2026-10-29-nvm-command-injection
event_id: brief-2026-10-29-nvm-command-injection
revision: 1
activity_at: "2026-10-29T07:09:42Z"
title: 'Node Version Manager: Command injection in nvm_ls (CVE-2026-118905)'
slug: 2026-10-nvm-command-injection
description: Node Version Manager (nvm) versions 0.31.2 through 0.40.5 are vulnerable to command injection via malicious version strings due to improper sanitization in the nvm_ls function when invoked with tools like nvm use or automated shell hooks.
date: "2026-10-29T07:09:42Z"
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
  validation_status: Checked against NVD details; no IOCs or specific event IDs provided by source.
cpes:
  - cpe:2.3:a:node_version_manager:node_version_manager:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - vulnerability
  - linux
  - macos
vendors:
  - Node Version Manager
products:
  - Node Version Manager (0.31.2 <= 0.40.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: This is reachable whenever an attacker-influenced version string is passed to nvm use... with GNU sed, the e command runs a shell command as the user.
    confidence_band: high
cves:
  - id: CVE-2026-118905
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118905
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade nvm to version 0.40.6 or later on all developer workstations and CI/CD agents.
      owner: IT Operations
      due: 48h
      evidence: 'Version 0.40.6 passes any version pattern containing # or a newline through the .nvmrc content parser first.'
  hunt_leads:
    - lead: Identify .nvmrc files containing shell metacharacters or newline characters.
      technique_id: T1059.004
      data_needed:
        - File system metadata and content scanning
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: 'A version string containing # (or \#) therefore closes the address early, and the rest of it is parsed as sed commands.'
---

CVE-2026-118905 describes a command injection vulnerability in nvm (Node Version Manager) versions 0.31.2 through 0.40.5. The `nvm_ls` function uses an improperly sanitized sed program to filter installed versions. By providing a version string containing specific characters such as `#`, an attacker can escape the intended sed address context and inject arbitrary commands. 

The vulnerability is triggered when an attacker-controlled version string is passed to commands like `nvm use`, `nvm which`, `nvm ls`, `nvm version`, `nvm run`, or `nvm exec`, or via the `NODE_VERSION` environment variable. Users employing auto-switching hooks (e.g., `cdnvm` or `load-nvmrc`) or scripts that pass raw `.nvmrc` contents to nvm commands are at particular risk, as changing to a directory containing a malicious `.nvmrc` file can trigger execution. The issue is resolved in version 0.40.6.

## Impact

Successful exploitation allows arbitrary command execution as the user running the nvm command or the shell hook. Using GNU sed, this can lead to direct shell command execution; using BSD sed, this can lead to unauthorized file read and write operations.

## Recommendation

* Patch nvm to version 0.40.6 or later immediately.
* Audit environments for scripts that pass file contents or environment variables directly to `nvm` commands without validation.
* Audit shell initialization files (`.bashrc`, `.zshrc`) for `cdnvm` or `load-nvmrc` hooks that automatically process `.nvmrc` files without sanitization.
