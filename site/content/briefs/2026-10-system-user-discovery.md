---
title: Detection of System User Discovery via query.exe
slug: 2026-10-system-user-discovery
description: Adversaries utilize the Windows utility 'query.exe' to perform system and Active Directory user discovery for situational awareness, facilitating further lateral movement and privilege escalation.
date: "2026-10-12T17:59:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - active-directory-discovery
  - lateral-movement
  - privilege-escalation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: Adversaries may use query.exe to gain situational awareness and perform Active Directory discovery on compromised endpoints.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1033/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1033/T1033.yaml
rules:
  - title: Detect System User Discovery via query.exe
    description: Detects the use of query.exe with command-line arguments intended to enumerate logged-in users, excluding standard local-only server queries.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM/EDR platform.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for query.exe discovery detection.
  hunt_leads:
    - lead: Search historical EDR logs for execution of query.exe in the past 30 days.
      technique_id: T1033
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as a known discovery technique.
---

The Windows binary `query.exe` is frequently leveraged by threat actors to perform system user discovery, a critical stage in the reconnaissance phase of an attack. By executing this utility, adversaries can enumerate currently logged-in users, mapping the environment to identify high-value targets or accounts with elevated privileges. This technique is often associated with Active Directory discovery efforts and has been documented in various campaigns, including activities related to Medusa Ransomware. While `query.exe` is a standard Windows component, its usage in command-line configurations targeting user information - specifically when not directed at local server contexts - serves as a high-fidelity signal for unauthorized reconnaissance. Defenders should focus on capturing full command-line arguments to distinguish between legitimate administrative troubleshooting and adversary-led discovery operations.

## Impact

Successful execution of this discovery technique allows attackers to gain critical situational awareness of the compromised endpoint and the broader network environment. By identifying active users, adversaries can optimize lateral movement paths and identify accounts with the appropriate permissions to escalate privileges or deploy ransomware, ultimately increasing the speed and efficacy of a security incident.

## Recommendation

* Deploy the provided Sigma rule to monitor for `query.exe` executions that include user enumeration parameters.
* Establish a baseline for administrative use of `query.exe` within your environment to tune out false positives originating from authorized IT management activities.
* Ensure EDR agents are configured to log full command-line strings and parent process information, as this metadata is essential for validating the intent behind `query.exe` execution.
