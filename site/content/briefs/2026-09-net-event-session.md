---
title: Potential Network Sniffing via Start-NetEventSession
slug: 2026-09-net-event-session
description: Adversaries may use the legitimate Windows PowerShell cmdlet Start-NetEventSession to capture network traffic and perform reconnaissance or credential theft.
date: "2026-09-03T13:41:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - discovery
  - network-sniffing
  - powershell
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1040
    technique_name: Network Sniffing
    evidence: Adversaries may attempt to capture network to gather information over the course of an operation. Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol.
    confidence_band: high
rules:
  - title: Detect Start-NetEventSession Cmdlet Usage
    description: Detects the execution of PowerShell scripts calling the Start-NetEventSession cmdlet, which can be used for unauthorized network packet capture.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1040
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for Start-NetEventSession to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: SigmaHQ repository rule metadata
  mitigation_plan:
    - priority: medium_term
      action: Enforce Script Block Logging via Group Policy
      owner: IT Operations
      addresses: Telemetry visibility
      evidence: Requires Script Block Logging per source definition
---

Attackers may abuse the built-in Windows PowerShell cmdlet 'Start-NetEventSession' to initiate unauthorized packet capture on a compromised host. This technique, classified as Network Sniffing (T1040), allows an adversary to monitor network traffic for sensitive information, such as plaintext credentials, configuration data, or internal network topology details. By leveraging native administrative tools, actors can often bypass legacy security controls that rely on signature-based detection of third-party sniffing utilities like Wireshark or tcpdump. Defenders should monitor PowerShell Script Block logs for the invocation of this cmdlet to identify post-exploitation sniffing activity. This detection is particularly critical in environments where unencrypted protocols are still in use, as the impact of such sniffing can lead to widespread credential compromise.

## Impact

Successful exploitation allows attackers to gain visibility into internal network communications, potentially leading to the interception of sensitive data, authentication tokens, and user credentials transmitted via insecure protocols. This provides a foundation for lateral movement and further escalation of privileges within the victim's environment.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to ensure visibility into cmdlet execution.
- Deploy the provided Sigma rule to detect the use of Start-NetEventSession and triage alerts against known network administration baselines.
- Audit administrative usage of network diagnostic tools to establish a baseline of expected behavior and reduce false positives from authorized IT operations.
