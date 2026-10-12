---
title: Abuse of Azure CLI for Entra ID User Management
slug: 2026-10-entra-user-mgmt-cli
description: Adversaries are leveraging the Azure CLI on compromised Windows hosts to manipulate Microsoft Entra ID user accounts for persistent access and stealthy operation.
date: "2026-10-12T18:05:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - identity-management
  - cloud-security
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Azure CLI
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Adversaries create new users so that their malicious activity does not interrupt the normal functions of the compromised users and can remain undetected.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries create new users so that their malicious activity does not interrupt the normal functions of the compromised users and can remain undetected.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This analytic detects the usage of the Azure CLI to interact with user accounts such as creating or deleting a user.
    confidence_band: high
rules:
  - title: Detect Azure CLI Entra User Management
    description: Detects the use of Azure CLI to perform user account management operations, which may indicate unauthorized persistent access attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1078.004
      - T1098
      - T1136.003
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
    - action: Deploy the Sigma rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided by Splunk ES content.
  hunt_leads:
    - lead: Search for Azure CLI commands interacting with 'ad' and 'user' keywords in historic logs.
      technique_id: T1136.003
      data_needed:
        - Process creation logs with command-line arguments
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Known technique for maintaining persistence.
---

Adversaries are increasingly using the Azure CLI (az.cmd) to interact with Microsoft Entra ID, specifically to perform user management tasks such as account creation or deletion. This technique allows attackers to establish persistence by creating new, malicious identities that remain under their control, even if original compromised accounts are remediated or locked. By performing these operations from an endpoint where the Azure CLI is already configured, attackers can leverage existing authentication tokens to bypass multi-factor authentication or credential prompts. This behavior represents a significant risk for environments where developers or administrators frequently use CLI tools to manage cloud infrastructure, as it blends malicious activity with standard administrative workflows. Defenders should prioritize identifying anomalous process execution patterns and unusual parent processes initiating Azure CLI commands.

## Attack Chain

1. An attacker gains initial access to a workstation or server used by an administrator.
2. The attacker performs internal reconnaissance to locate stored Azure CLI configuration files or active session tokens.
3. The attacker executes the Azure CLI binary (az.cmd) via the command line or an automated script.
4. The process executes using the context and permissions of the currently logged-in user.
5. The attacker invokes the 'ad user create' or similar account management modules within the Azure CLI.
6. The command communicates with the Microsoft Entra ID API to successfully provision a new identity.
7. The attacker verifies the creation of the new account and proceeds to utilize it for secondary persistence or data exfiltration.
8. The attacker remains active in the cloud environment, potentially utilizing the newly created account for future operations.

## Impact

The abuse of Azure CLI for identity manipulation can lead to unauthorized access, privilege escalation, and persistent entry into a victim's cloud tenant. Successful exploitation enables attackers to maintain long-term access despite credential resets on compromised endpoints. While specific victim counts are not provided, this technique is frequently observed in post-compromise scenarios targeting organizations with significant cloud footprints, particularly those relying on Microsoft Entra ID.

## Recommendation

* Deploy the provided Sigma rule to detect suspicious Azure CLI commands targeting user management.
* Establish a baseline for authorized administrative service accounts and users permitted to interact with Microsoft Entra ID via CLI.
* Integrate Sysmon Event ID 1 and Windows Event Log 4688 to capture complete process command-line execution telemetry.
* Investigate occurrences of Azure CLI binaries being launched by unexpected parent processes or in contexts that deviate from established administrative patterns.
