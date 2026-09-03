---
title: Command Injection in MOOS-IvP uMemWatch
slug: 2026-09-moos-ivp-umemwatch-injection
description: MOOS-IvP uMemWatch through version 24.8.1 is vulnerable to command injection due to improper sanitization of MOOS client names, allowing arbitrary code execution.
date: "2026-09-03T23:24:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:moos-ivp:umemwatch:*:*:*:*:*:*:*:*
vendors:
  - MOOS-IvP
products:
  - uMemWatch (<= 24.8.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject shell metacharacters into client names to execute arbitrary commands as the uMemWatch process user.
    confidence_band: high
cves:
  - id: CVE-2026-85426
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85426
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade MOOS-IvP software to version > 24.8.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-85426 documentation
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest version
      owner: IT Operations
      addresses: CVE-2026-85426
      evidence: Vulnerability remediation requirement
---

MOOS-IvP uMemWatch, a component used in the MOOS-IvP autonomous vehicle control software suite, is susceptible to a critical command injection vulnerability (CVE-2026-85426) affecting all versions up to and including 24.8.1. The vulnerability arises because the application fails to properly sanitize user-supplied MOOS client names before incorporating them into shell commands invoked via system calls. By crafting a MOOS client name containing shell metacharacters, an attacker can escape the intended command string and execute arbitrary commands with the privileges of the user running the uMemWatch process. This vulnerability is particularly concerning in autonomous system environments where uMemWatch often runs with elevated privileges to monitor system integrity. Defenders should prioritize updating to the patched version of the software and monitor for unexpected child processes spawned by the uMemWatch binary.

## Impact

Successful exploitation allows for full command execution on the host running the uMemWatch process. Given the role of MOOS-IvP in autonomous vehicle systems, this could lead to unauthorized control of system resources, manipulation of sensor data, or total system compromise, resulting in mission failure or physical equipment hazards.

## Recommendation

* Patch CVE-2026-85426 by upgrading the MOOS-IvP suite to a version greater than 24.8.1 immediately.
* Audit process execution logs for instances where uMemWatch spawns unexpected shells or system utilities (e.g., sh, bash, python).
* Enforce principle of least privilege by running the uMemWatch process with a dedicated, non-privileged service account.
