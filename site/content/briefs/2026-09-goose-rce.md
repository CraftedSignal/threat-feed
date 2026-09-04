---
title: Remote Code Execution in Goose 1.37.0 via Malicious Recipes
slug: 2026-09-goose-rce
description: The goose utility version 1.37.0 contains a vulnerability where insecure handling of recipe stdio extensions and retry.checks permits unvalidated arbitrary shell command execution.
date: "2026-09-04T15:28:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:goose_project:goose:1.37.0:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - supply-chain
products:
  - goose (1.37.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can distribute malicious recipes that execute shell commands as the user running goose.
    confidence_band: high
cves:
  - id: CVE-2026-85623
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85623
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory systems running goose 1.37.0
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects version 1.37.0
  mitigation_plan:
    - priority: immediate
      action: Restrict usage of untrusted recipes within the environment
      owner: SOC
      addresses: CVE-2026-85623
      evidence: Vulnerability involves arbitrary command execution via malicious recipes
---

The goose utility, specifically version 1.37.0, contains a critical security flaw allowing for arbitrary command execution. The application processes recipe files that define stdio extensions and retry.checks configurations without performing necessary security inspections or validation. An attacker capable of providing a crafted recipe file to a user can bypass existing security scanners, which fail to examine the extensions and retry logic within these configurations. When goose processes the malicious recipe, it executes the embedded shell commands in the context of the user running the goose binary. This vulnerability enables attackers to achieve code execution on any system where a user interacts with a malicious goose recipe file. Defenders should be aware that standard security scanning of recipes may not be sufficient to catch these specific vectors.

## Impact

Successful exploitation allows an attacker to execute arbitrary shell commands on the host system, potentially leading to full system compromise, data exfiltration, or persistence, depending on the privileges of the user running the goose utility. This vulnerability affects all platforms where version 1.37.0 is deployed.

## Recommendation

Prioritized actions for security teams:
* Identify and inventory all deployments of goose version 1.37.0.
* Until an official patch is released, restrict users from importing or executing untrusted goose recipes.
* Audit file system activity for unexpected processes spawned by the goose binary.
* Monitor for suspicious shell execution patterns where the parent process is the goose binary.
