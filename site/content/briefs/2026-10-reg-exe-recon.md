---
brief_id: brief-2026-10-21-reg-exe-recon
event_id: brief-2026-10-21-reg-exe-recon
revision: 1
activity_at: "2026-10-21T00:48:29Z"
title: Configuration and Service Reconnaissance via Reg.exe
slug: 2026-10-reg-exe-recon
description: Adversaries utilize the Windows command-line registry utility to perform system and service reconnaissance, aiding in local environment discovery and persistence identification.
date: "2026-10-21T00:48:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - discovery
  - windows
  - reconnaissance
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1012
    technique_name: Query Registry
    evidence: Adversaries may interact with the Windows registry to gather information about credentials, the system, configuration, and installed software.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1007
    technique_name: System Service Discovery
    evidence: Detects the usage of reg.exe in order to query reconnaissance information from the registry.
    confidence_band: high
rules:
  - title: Detect Configuration and Service Reconnaissance via Reg.exe
    description: Detects usage of 'reg.exe' to query registry keys related to system configuration, services, and persistence mechanisms.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1007
      - T1012
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule 970007b7-ce32-49d0-a4a4-fbef016950bd to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Rule defined in brief
  hunt_leads:
    - lead: Search for excessive 'reg query' activity in process logs
      technique_id: T1012
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: General reconnaissance TTP mapping
---

Adversaries frequently leverage the legitimate Windows utility `reg.exe` to perform reconnaissance activities. By querying sensitive registry keys, an attacker can enumerate installed software, system configuration details, and potential persistence mechanisms. This behavior is commonly observed in the early stages of a post-compromise environment, as it allows threat actors to map out the system's security posture and identify interesting services or applications for further exploitation. Security teams should monitor for the combination of `reg.exe` execution with specific command-line arguments targeting keys related to auto-start locations, service configurations, and system policies.

## Attack Chain

1. Initial access is gained to the target system via a user-level shell or remote access tool.
2. The attacker identifies the `reg.exe` utility in the system path.
3. The attacker executes `reg query` to target specific registry hives, such as `HKCU` or `HKLM`.
4. The query focuses on paths like `currentVersion\run` to identify persistence mechanisms.
5. The attacker proceeds to query `currentcontrolset\services` to identify installed system services.
6. The gathered registry data is exfiltrated or parsed locally to identify future targets.
7. The final objective includes leveraging the discovered information for privilege escalation or lateral movement.

## Impact

Successful reconnaissance allows an attacker to build an accurate profile of the target environment, enabling the identification of weak configurations, security product paths, and persistent entry points. This data significantly reduces the time required for an attacker to move from initial access to full domain compromise.

## Recommendation

* Deploy the provided Sigma rule to detect `reg.exe` usage targeting sensitive registry hives in your SIEM.
* Establish an allowlist of administrative tools or management scripts that legitimately use `reg.exe` to query system configurations to reduce false positives.
* Audit endpoint telemetry for frequent `reg query` commands from non-administrative service accounts.
