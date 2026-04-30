---
title: Emissary OS Command Injection Vulnerability (CVE-2026-35581)
slug: 2026-04-emissary-command-injection
description: Emissary, a P2P data-driven workflow engine, is vulnerable to OS command injection due to insufficient sanitization of the PLACE_NAME parameter in versions prior to 8.39.0, allowing for arbitrary command execution.
date: "2026-04-07T17:16:33Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - command injection
  - emissary
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35581
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35581
  - https://github.com/NationalSecurityAgency/emissary/security/advisories/GHSA-6c37-7w4p-jg9v
rules:
  - title: Detect Suspicious PLACE_NAME Parameter Modification
    description: Detects modifications to the PLACE_NAME parameter in Emissary configuration files that contain shell metacharacters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
  - title: Detect Emissary Command Execution via /bin/sh -c
    description: Detects command execution events originating from the emissary process with /bin/sh -c as a parent.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Emissary is a P2P-based data-driven workflow engine. Prior to version 8.39.0, a critical vulnerability, CVE-2026-35581, existed within the Executrix utility class. This class constructs shell commands by concatenating configuration-derived values, specifically the PLACE_NAME parameter, without proper sanitization. The inadequate sanitization process only replaced spaces with underscores, leaving shell metacharacters (;, |, $, `, (, ), etc.) vulnerable to injection. This flaw allows attackers to inject arbitrary commands into the /bin/sh -c command execution. Emissary version 8.39.0 addresses and resolves this command injection vulnerability. This vulnerability allows for privilege escalation to an attacker with high priviledges.

## Attack Chain

1. An attacker with high privileges gains access to the Emissary configuration.
2. The attacker modifies the PLACE_NAME configuration parameter to include malicious shell metacharacters (e.g., `; whoami > /tmp/output`).
3. The system uses the modified PLACE_NAME parameter to construct a shell command.
4. The Executrix utility class executes the command via `/bin/sh -c`.
5. The injected shell metacharacters allow the attacker's command (`whoami`) to execute.
6. The output of the command is written to `/tmp/output`, confirming arbitrary command execution.
7. The attacker can then use the initial foothold to escalate privileges further.
8. The attacker gains full control of the affected system.

## Impact

Successful exploitation of CVE-2026-35581 allows a high-privilege attacker to achieve arbitrary command execution on the Emissary server. The CVSS v3.1 score of 7.2 indicates a high level of severity. Depending on the Emissary deployment, this could lead to data breaches, service disruption, or complete system compromise. The number of victims and specific sectors targeted are currently unknown.

## Recommendation

*   Upgrade Emissary to version 8.39.0 or later to remediate CVE-2026-35581.
*   Monitor Emissary configuration files for unauthorized modifications to the PLACE_NAME parameter.
*   Implement input validation and sanitization for all configuration parameters to prevent command injection attacks.
*   Deploy the Sigma rule `Detect Suspicious PLACE_NAME Parameter Modification` to detect exploitation attempts.
*   Enable command-line auditing to log all commands executed by the Emissary process.
