---
title: Command Injection in Grav Git Sync Plugin
slug: 2026-10-grav-git-sync-command-injection
description: Grav Git Sync versions 1.0.2 through 3.4.12 contain a command injection vulnerability allowing authenticated users to execute OS commands via malicious profile inputs.
date: "2026-10-12T18:35:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:grav:git_sync:*:*:*:*:*:*:*:*
tags:
  - web-application
  - command-injection
  - cve-2026-109318
vendors:
  - Grav
products:
  - Git Sync (1.0.2 - 3.4.12)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated content editors can execute OS commands by injecting shell substitutions into profile fields.
    confidence_band: high
cves:
  - id: CVE-2026-109318
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109318
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review and restrict administrative privileges for Grav CMS users to mitigate authenticated exploitation risk
      owner: SOC
      due: 24h
      evidence: Vulnerability requires authenticated content editor access
  mitigation_plan:
    - priority: immediate
      action: Upgrade Grav Git Sync plugin to version 3.4.13 or later
      owner: IT Operations
      addresses: CVE-2026-109318
      evidence: Source identifies vulnerability in versions 1.0.2 through 3.4.12
---

Grav Git Sync plugin versions 1.0.2 through 3.4.12 are susceptible to a command injection vulnerability (CVE-2026-109318). The flaw exists when the plugin is configured with 'gravuser' or 'gravfull' author mode, which facilitates Git commits using user-provided profile metadata. An authenticated content editor can inject shell metacharacters into the 'username', 'full name', or 'email' fields within the user profile. The application improperly sanitizes these inputs before passing them to the 'git commit --author' command via the PHP 'exec()' function. Successful exploitation allows an attacker to execute arbitrary system commands under the security context of the web-server process, potentially leading to unauthorized system access, data exfiltration, or further lateral movement within the hosting environment.

## Impact

This vulnerability impacts organizations utilizing the Grav CMS with the affected Git Sync plugin versions. Because the vulnerability requires authentication, the impact is primarily lateral escalation from a compromised content editor account to full OS-level control on the web server.

## Recommendation

* Update the Grav Git Sync plugin to a version later than 3.4.12 as soon as a security patch is available.
* Audit user profiles within the Grav CMS for any characters that deviate from standard alphanumeric patterns in 'username', 'full name', or 'email' fields.
* Restrict access to the Grav CMS administrative interface to trusted users to mitigate the risk of authenticated exploitation.
* Monitor web server logs and process execution logs for suspicious child processes spawned by the web-server user (e.g., www-data, apache, nginx) following user profile update actions.
