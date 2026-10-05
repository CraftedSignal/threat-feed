---
title: Detection of Unauthorized Remote Access Software Usage
slug: 2026-10-remote-access-software-usage
description: Adversaries frequently abuse legitimate remote access tools to establish persistent command-and-control, facilitate lateral movement, and deploy ransomware within compromised environments.
date: "2026-10-05T12:10:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote-access
  - command-and-control
  - persistence
  - rmm
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Adversaries often use remote access tools like AnyDesk, GoToMyPC, LogMeIn, and TeamViewer to maintain unauthorized access.
    confidence_band: high
rules:
  - title: Detect Unauthorized Remote Access Software Execution
    description: Detects the execution of known remote access software binaries commonly abused for persistence and command-and-control.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy process-level detection for unauthorized RMM tools.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic requirement for endpoint visibility.
  hunt_leads:
    - lead: Search for unknown processes spawning remote access binaries.
      technique_id: T1219
      data_needed:
        - ParentProcessName
        - ProcessName
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers often use RMM as secondary persistence.
  mitigation_plan:
    - priority: medium_term
      action: Strictly limit use of RMM tools to hardened, managed administrative workstations.
      owner: IT Operations
      addresses: T1219
      evidence: General security best practice for minimizing attack surface.
---

Adversaries frequently abuse legitimate remote access software (RATs/RMMs) to maintain unauthorized access to victim environments. Tools such as AnyDesk, TeamViewer, GoToMyPC, and LogMeIn are commonly repurposed by threat actors, including groups like Scattered Spider and developers of Cactus and Interlock ransomware, to bypass traditional security controls. Because these applications are digitally signed and often used by IT support staff, they can remain undetected for extended periods. Defenders must monitor for the execution of these binaries, especially when they originate from unexpected user contexts or lack a legitimate business justification. This analytic identifies the execution of such software by cross-referencing process telemetry from EDR agents against a managed list of known remote access utilities.

## Impact

Successful deployment of unauthorized remote access software allows attackers to achieve persistent system control, execute interactive commands, bypass local authentication, exfiltrate sensitive data, and provide a stable conduit for the deployment of secondary payloads, including ransomware. If left undetected, this visibility gap facilitates prolonged attacker dwell time and increases the likelihood of catastrophic data exfiltration and business disruption.

## Recommendation

* Deploy the provided Sigma rule to identify unauthorized remote access software execution across the endpoint fleet.
* Populate the `remote_access_software` lookup table with all enterprise-approved remote access tools to ensure proper filtering.
* Enable EDR process creation logging (e.g., Sysmon Event ID 1) and map these logs to the Endpoint data model within the SIEM to support this detection.
* Establish an exception management process using a lookup or KVStore to suppress alerts for authorized IT administration tools while maintaining visibility into non-standard process executions.
