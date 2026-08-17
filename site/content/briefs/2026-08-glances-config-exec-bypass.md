---
title: Incomplete Fix for Glances Configuration Command Execution Bypass
slug: 2026-08-glances-config-exec-bypass
description: Glances versions up to 4.5.5 contain a vulnerability where the --disable-config-exec flag fails to sanitize shell operators in on-alert action commands, allowing arbitrary command execution or file redirection.
date: "2026-08-17T18:46:46Z"
lastmod: "2026-08-17T18:46:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - security-bypass
  - command-injection
  - local-privilege-escalation
vendors:
  - Glances
products:
  - Glances (<= 4.5.5)
  - Glances (4.5.2 to 4.5.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The hardening was not applied to the on-alert action command path, which reads its command lines from the same configuration file.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The renderer does not escape pipe characters and the downstream execution sink interprets shell operators by default, an unprivileged local attacker can inject arbitrary shell commands.
    confidence_band: high
cves:
  - id: CVE-2026-68519
  - id: CVE-2026-53925
    cvss: 7.8
    epss: 0.00137
references:
  - https://github.com/advisories/GHSA-59fj-m2j6-hcxh
  - https://github.com/advisories/GHSA-73wf-9vmv-5pv9
  - CVE-2026-62982
  - CVE-2026-32608
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit glanses.conf for suspicious entries in user_critical_action or similar parameters.
      owner: SOC
      due: 48h
      evidence: Source documentation identifies glanses.conf as the trust boundary.
  mitigation_plan:
    - priority: immediate
      action: Restrict filesystem permissions on the glances.conf configuration file.
      owner: IT Operations
      addresses: CVE-2026-68519
      evidence: Configuration file modification is the primary attack vector.
updates:
  - at: "2026-08-17T18:46:57Z"
    level: L2
    summary: added coverage for Glances (4.5.2 to 4.5.5)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-73wf-9vmv-5pv9
---

Glances version 4.5.5 and earlier versions contain a vulnerability identified as CVE-2026-68519, which acts as an incomplete fix for a previously reported issue (CVE-2026-53925). While the `--disable-config-exec` flag successfully restricts shell operator interpretation in Application Monitoring Plugin (AMP) modules, the restriction is not applied to the 'on-alert action' command path. 

Defenders should note that Glances reads command lines from the `glances.conf` file. If an attacker gains write access to this configuration file, they can inject shell operators such as `&&` (chaining), `|` (pipe), or `>` (file redirection) into alert action fields. Because the `glances/actions.py` module fails to pass the `allow_operators` constraint to the `secure_popen()` function in the alert action code path, these injected commands are executed with the privileges of the Glances process. This vulnerability effectively negates the security guarantees provided by the `--disable-config-exec` flag.

## Impact

Successful exploitation allows an attacker with access to modify the Glances configuration file to achieve arbitrary command execution or unauthorized file writes. This represents a significant escalation of privilege or persistence mechanism, as the commands execute under the security context of the Glances daemon or user process.

## Recommendation

- Upgrade Glances to the version addressing CVE-2026-68519 as soon as it becomes available.
- Audit the integrity of the `glances.conf` file across all monitored environments to ensure no unauthorized alert actions have been injected.
- Restrict write access to the `glances.conf` file to a minimal set of highly privileged administrative users.
- Monitor for unexpected process creation events spawned by the `glances` process, specifically processes launched as children of the main Glances application.
