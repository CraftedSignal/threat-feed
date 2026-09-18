---
title: Detection of Unauthorized SSH Authorized Keys Modification
slug: 2026-09-ssh-persistence
description: Adversaries modify SSH authorized_keys files to establish persistent access and facilitate lateral movement by injecting unauthorized public keys for password-less authentication.
date: "2026-09-18T19:22:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - lateral-movement
  - ssh
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may modify it to maintain persistence on a victim host by adding their own public key(s).
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: The detection rule identifies unauthorized changes to these files, excluding benign processes, to flag potential threats, focusing on persistence and lateral movement tactics.
    confidence_band: high
rules:
  - title: Detect Unauthorized SSH Authorized Keys Modification
    description: Detects unauthorized modification or creation of SSH authorized_keys files, excluding known benign administrative and automation processes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.004
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection rule requirements and exclusion list.
  hunt_leads:
    - lead: Identify all instances of modified SSH keys in the last 30 days
      technique_id: T1098.004
      data_needed:
        - File integrity logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as a critical persistence mechanism.
  mitigation_plan:
    - priority: short_term
      action: Review SSH configurations and remove unauthorized keys
      owner: IT Operations
      addresses: T1098.004
      evidence: Source recommends this as a core remediation step.
---

Adversaries frequently target SSH configuration files, specifically the 'authorized_keys' and 'authorized_keys2' files, to maintain long-term access to compromised Linux and macOS systems. By appending their own public keys to these files, threat actors can bypass traditional password authentication requirements and establish a stealthy, persistent presence. This technique is often employed after initial access has been achieved, enabling subsequent lateral movement across the network. Defenders must distinguish between these malicious modifications and legitimate administrative activities performed by automated deployment tools, configuration management agents, or standard system utilities. Monitoring for file modification events on these specific paths provides high-fidelity detection opportunities, provided that legitimate tooling is properly filtered based on organizational baselines.

## Attack Chain

1. The attacker gains initial code execution on a Linux or macOS target host.
2. The attacker performs local reconnaissance to locate SSH configuration directories, typically targeting ~/.ssh/.
3. The attacker prepares a malicious SSH public key payload to be injected into the target file.
4. The attacker uses standard system utilities or a custom script to append the payload to 'authorized_keys' or 'authorized_keys2'.
5. The file modification triggers an audit or endpoint event for a file write operation.
6. The attacker subsequently logs into the server using the private key corresponding to the newly added public key.
7. The attacker leverages this persistent access to conduct further internal reconnaissance or exfiltrate sensitive data.

## Impact

Successful exploitation results in unauthorized, persistent access to target systems. This grants an attacker the ability to bypass password-based security controls, maintain access despite credential changes, and move laterally to other systems within the environment. This activity is a hallmark of post-exploitation phases in breaches, often observed in servers, workstations, and CI/CD infrastructure.

## Recommendation

Prioritize the implementation of file integrity monitoring on all critical Linux and macOS hosts to track access to SSH configuration files. Deploy the provided Sigma rule to alert on unauthorized modifications, ensuring that specific internal automation tools and binary paths used by the organization are added to the exclusion list to maintain a low false-positive rate. In the event of an alert, initiate an immediate incident response workflow to identify the originating process and verify the legitimacy of the injected public key.
