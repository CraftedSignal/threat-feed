---
title: Detection of Unauthorized Local Account Creation on macOS
slug: 2026-09-macos-account-creation
description: This brief details the detection of local account creation on macOS systems, a technique often used by adversaries to establish persistence or facilitate privilege escalation through administrative utilities.
date: "2026-09-04T18:01:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - macos
  - endpoint-security
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Monitoring the creation of local accounts is crucial for a SOC as it can indicate unauthorized access or lateral movement within the network.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136
    technique_name: Create Account
    evidence: If confirmed malicious, this activity could allow an attacker to establish persistence, escalate privileges, or gain unauthorized access to sensitive systems and data.
    confidence_band: high
references:
  - https://osquery.readthedocs.io/en/stable/deployment/process-auditing/
  - https://ss64.com/mac/sysadminctl.html
  - https://ss64.com/mac/dseditgroup.html
  - https://ss64.com/mac/dscl.html
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy TA-OSquery and enable monitoring for administrative process execution
      owner: Detection Engineering
      due: 72h
      evidence: Required for data model population as per implementation documentation
  hunt_leads:
    - lead: Search for historical instances of sysadminctl or dscl account creation to establish a baseline
      technique_id: T1136.001
      data_needed:
        - Process creation events from Osquery/Endpoint logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Identification of new local account creation is necessary for persistence detection
  mitigation_plan:
    - priority: medium
      action: Enforce strict Least Privilege policies on endpoints
      owner: IT Operations
      addresses: Privilege escalation via new accounts
      evidence: Standard security hardening
  gaps:
    - Telemetry gap if endpoint management tools do not properly report process arguments
---

Monitoring the creation of new local user accounts on macOS is a critical defense requirement, as this activity is frequently associated with persistence establishment, lateral movement, or unauthorized privilege escalation. Attackers often leverage built-in administrative utilities such as `sysadminctl`, `dscl`, `dseditgroup`, or `createhomedir` to add accounts or modify group memberships silently. While these tools are essential for legitimate system administration and endpoint management, their use outside of defined lifecycle windows - such as initial provisioning or authorized maintenance - often signals malicious intent. Detection engineers should focus on identifying these process executions to prevent long-term system compromise. The provided detection logic is intended for integration within environments using Osquery for endpoint telemetry, requiring the deployment of the TA-OSquery add-on to ensure proper mapping to common data models.

## Attack Chain

1. Adversary gains initial access to a macOS endpoint.
2. Adversary identifies the need for persistent or elevated access.
3. Adversary executes a command-line tool, such as `sysadminctl -addUser`, to create a new local account.
4. Adversary may use `dseditgroup` to add the newly created account to the 'admin' group for elevated privileges.
5. Adversary uses `dscl -create` to further configure user attributes or metadata for the account.
6. Account is successfully created on the local system, providing a backdoor for future access.
7. Adversary uses the new credentials to authenticate to the machine and perform further post-exploitation activities.

## Impact

Unauthorized creation of local accounts allows attackers to maintain persistent access to a compromised system, effectively bypassing temporary credential expirations or single-use access tokens. This can lead to full host compromise, exfiltration of sensitive organizational data, and the facilitation of lateral movement throughout the network. If left undetected, persistent accounts may remain active for extended periods, complicating remediation efforts and increasing the total scope of an incident.

## Recommendation

- Implement monitoring for administrative processes on macOS endpoints using Osquery.
- Deploy the TA-OSquery add-on to all indexers and universal forwarders to ensure endpoint data is correctly ingested into the Enterprise Security data models.
- Establish a baseline for authorized account creation activity to minimize false positives from standard endpoint management software.
- Investigate any occurrences of `sysadminctl`, `dscl`, or `dseditgroup` execution on endpoints that do not originate from authorized deployment or administration process trees.
