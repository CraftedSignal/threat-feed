---
title: Detection of Windows Guest Account Activation via Net.exe
slug: 2026-10-windows-guest-account-enabled
description: Adversaries may enable the built-in Windows guest account using the net.exe utility to establish persistent, low-profile access to a target system.
date: "2026-10-12T18:07:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - privilege-escalation
  - initial-access
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries may enable this account to maintain persistent, low-profile access to a system.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1078.001/T1078.001.yaml
rules:
  - title: Detect Windows Guest Account Enabled Via Net.exe
    description: Detects the use of net.exe to enable the guest account on Windows systems.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1078.001
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
    - action: Deploy Sigma rule to detect guest account activation.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line for detection.
  mitigation_plan:
    - priority: short_term
      action: Audit all local user accounts and ensure the Guest account is disabled.
      owner: IT Operations
      addresses: T1078.001
      evidence: Source identifies guest account activation as a persistent threat.
---

The Windows guest account is a default, built-in account designed with heavily restricted permissions and limited system access. By default, this account is disabled on all Windows operating systems. Adversaries often target this account to maintain persistent, low-profile access, bypass standard user auditing, or facilitate lateral movement. Enabling this account allows an attacker to return to a compromised host using a legitimate, pre-existing local account, which may circumvent security controls that monitor for the creation of new, anomalous user accounts. The activation is typically performed by running the Windows utility 'net.exe' with specific administrative parameters. Defenders should monitor for these command-line executions to identify unauthorized privilege escalation or persistence activities within their environment.

## Impact

Successful activation and exploitation of the guest account can provide attackers with a foothold to perform malicious activities, including malware installation, file system manipulation, sensitive data exfiltration, or further system control. This technique is particularly concerning in environments where the guest account is not routinely managed or audited, as it provides a stealthy mechanism for maintaining long-term access.

## Recommendation

Detection engineering teams should monitor process creation events for the execution of net.exe with arguments intended to modify user account status.

- Deploy the Sigma rule in this brief to identify potential unauthorized activation of the guest account.
- Enable Sysmon or Windows Security Event ID 4688 to capture complete process command-line telemetry.
- Establish an allowlist for known administrative or automated maintenance accounts authorized to manage local user accounts to reduce noise in security alerts.
