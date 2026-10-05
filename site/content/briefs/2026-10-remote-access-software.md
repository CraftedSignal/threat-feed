---
title: Detection of Unauthorized Remote Access Software Usage
slug: 2026-10-remote-access-software
description: This detection monitors for the creation of files associated with known remote access utilities, which adversaries frequently deploy to establish C2 channels and persistent access.
date: "2026-10-05T12:09:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - persistence
  - remote-monitoring-management
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Adversaries often use remote access tools like AnyDesk, GoToMyPC, LogMeIn, and TeamViewer to maintain unauthorized access.
    confidence_band: high
rules:
  - title: Detect Remote Access Software Installation
    description: Detects the creation of files on disk identified as belonging to known remote access software utilities.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review and update the remote_access_software lookup table to include current approved utilities.
      owner: Detection Engineering
      due: 48h
      evidence: Requires updates to reduce false positives.
  hunt_leads:
    - lead: Search for unknown binaries in temp directories with file names matching known remote access tools.
      technique_id: T1219
      data_needed:
        - Sysmon Event ID 11
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries frequently drop tools to temporary directories.
  mitigation_plan:
    - priority: short_term
      action: Implement strict application control or allowlisting for remote access software.
      owner: IT Operations
      addresses: T1219
      evidence: Prevents execution of unauthorized remote access binaries.
---

Adversaries frequently employ legitimate remote access software (RATs) such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer to maintain unauthorized access to compromised endpoints. By leveraging these tools, attackers can bypass traditional perimeter controls, as the traffic often blends with legitimate administrative activity. The deployment of these utilities usually occurs after initial access is achieved, serving as a secondary persistent backdoor or a mechanism for interactive operator control.

This detection focuses on identifying the filesystem-level arrival of these tools, specifically monitoring for executables, installers, and scripts identified via a managed lookup table of known remote access utilities. Because these tools are often utilized by legitimate administrators, the detection requires careful tuning via exception lists to avoid noise. The presence of these files is a high-fidelity indicator that requires immediate investigation to determine if the deployment was authorized by internal IT or performed by an unauthorized third party.

## Attack Chain

1. Initial access is gained through phishing, exploitation of a public-facing application, or compromised credentials.
2. The attacker performs initial reconnaissance to identify system architecture and installed security software.
3. The attacker downloads or drops the remote access utility installer (e.g., .exe, .msi, or .pkg) to a temporary directory.
4. The installer is executed to register the remote access service, creating persistent registry keys or startup entries.
5. The remote access agent initiates an outbound connection to the vendor's command-and-control infrastructure.
6. The attacker uses the persistent remote access session to conduct lateral movement and harvest credentials.
7. Final objectives, such as data exfiltration or ransomware deployment, are executed via the established remote session.

## Impact

Successful deployment of unauthorized remote access software grants an attacker persistent, interactive control over the affected system. This facilitates long-term presence, bypass of network segmentation, and the ability to exfiltrate sensitive data or deploy further payloads, often resulting in widespread environment compromise and significant operational disruption.

## Recommendation

1. Deploy file-creation monitoring (Sysmon Event ID 11 or equivalent EDR telemetry) focusing on paths associated with user-writeable directories.
2. Maintain a centralized, organizational list of authorized remote access utilities to act as an allowlist against the `remote_access_software` lookup.
3. Audit the current `remote_access_software_usage_exceptions` list to ensure all legitimate administrative tools are properly excluded.
4. Use the provided Splunk analytic to monitor for unauthorized arrivals of new binaries from the identified remote utility categories.
