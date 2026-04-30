---
title: Windmill Missing Authorization Vulnerability (CVE-2026-22683)
slug: 2024-02-29-windmill-auth-bypass
description: Windmill versions 1.56.0 through 1.614.0 contain a missing authorization vulnerability (CVE-2026-22683) that allows users with the Operator role to bypass intended restrictions and perform unauthorized entity creation and modification actions via the backend API, potentially leading to privilege escalation and remote code execution.
date: "2026-04-07T17:16:27Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - windmill
  - authorization-bypass
  - privilege-escalation
  - remote-code-execution
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-22683
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22683
rules:
  - title: Detect Windmill Unauthorized Entity Creation
    description: Detects attempts to create scripts, flows, apps, or raw_apps from Operator accounts via the Windmill API, indicating a potential exploitation of CVE-2026-22683.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Windmill Job Execution of Newly Created Entities
    description: Detects the execution of Windmill jobs that were created recently, which may be related to exploitation of CVE-2026-22683.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Windmill, a low-code internal tool platform, contains a critical missing authorization vulnerability, tracked as CVE-2026-22683, affecting versions 1.56.0 through 1.614.0. The vulnerability stems from a failure to properly enforce role-based access controls within the backend API. Specifically, users assigned the "Operator" role, who are intended to have limited privileges and be restricted from creating or modifying entities, can bypass these restrictions.  This allows Operators to create and modify scripts, flows, apps, and raw_apps, effectively exceeding their intended permissions. Given that Operators can also execute scripts through the jobs API, this authorization bypass facilitates a direct path to privilege escalation and potentially remote code execution within the Windmill environment. Defenders should prioritize patching and detection efforts to mitigate this risk.

## Attack Chain

1. An attacker compromises or is assigned an "Operator" role within the Windmill platform.
2. The attacker authenticates to the Windmill backend API using their Operator credentials.
3. The attacker crafts a malicious API request to create a new script, flow, app, or raw_app, bypassing the intended authorization checks for Operator roles.
4. The Windmill API processes the request without properly validating the Operator's permissions, allowing the entity creation to proceed.
5. The attacker creates a script containing malicious code designed to escalate privileges or execute arbitrary commands.
6. The attacker utilizes the jobs API to execute the newly created malicious script.
7. The script executes with elevated privileges within the Windmill deployment environment.
8. The attacker achieves remote code execution, potentially compromising the entire Windmill instance and connected resources.

## Impact

A successful exploitation of CVE-2026-22683 can lead to complete compromise of the Windmill instance. An attacker leveraging an Operator account can gain remote code execution capabilities. The missing authorization can lead to full control over the Windmill instance, potentially affecting all applications, flows, and scripts managed within the platform. Given the nature of Windmill as an internal tool platform, this could expose sensitive internal data and systems to unauthorized access. The number of affected organizations depends on the adoption rate of Windmill within the affected version range.

## Recommendation

*   Immediately upgrade Windmill instances to a patched version beyond 1.614.0 to remediate CVE-2026-22683.
*   Implement the Sigma rule `Detect Windmill Unauthorized Entity Creation` to detect attempts to create scripts, flows, apps, or raw_apps from Operator accounts via the API.
*   Implement the Sigma rule `Detect Windmill Job Execution of Newly Created Entities` to detect the execution of scripts, flows, apps or raw_apps that were recently created.
*   Monitor Windmill API logs for suspicious activity related to entity creation and modification, focusing on requests originating from Operator accounts.
