---
title: Detection of DSInternals PowerShell Module Usage
slug: 2026-09-dsinternals-posh
description: This brief documents detection logic for the DSInternals PowerShell module, a toolkit frequently leveraged by threat actors to perform unauthorized offline manipulation of Active Directory databases and extraction of cryptographic material.
date: "2026-09-03T12:35:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - powershell
  - credential-access
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects execution and usage of the DSInternals PowerShell module.
    confidence_band: high
rules:
  - title: Detect DSInternals PowerShell Module Cmdlet Execution
    description: Detects the use of DSInternals PowerShell cmdlets, which may indicate unauthorized AD database manipulation or credential harvesting attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to capture DSInternals module usage.
      owner: Detection Engineering
      due: 48h
      evidence: Required to surface potentially malicious PowerShell activity.
  hunt_leads:
    - lead: Search historic logs for the listed DSInternals cmdlets to identify baseline activity or previous compromise.
      technique_id: T1059.001
      data_needed:
        - PowerShell Script Block logs (Event ID 4104)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Tooling is known to be used by attackers for post-compromise activity.
---

The DSInternals PowerShell module is an advanced toolkit designed for auditing and manipulating Active Directory (AD) and Azure Active Directory (AAD) internals. While intended for administrative and security research purposes, its capabilities are highly attractive to attackers post-compromise. The module provides functionality for extracting domain secrets, manipulating the NTDS.DIT database file offline, recovering domain controllers from Install from Media (IFM) backups, and performing password auditing. Defenders should focus on identifying the invocation of these specific cmdlets, as their presence in a production environment, especially when executed by non-administrative service accounts or in an ad-hoc manner, often indicates credential harvesting or persistence maintenance activities. Monitoring PowerShell Script Block logs is essential to surface these commands, as they are often executed in-memory to evade traditional disk-based detection.

## Impact

Successful usage of these tools can result in complete domain compromise through the extraction of NTDS.DIT files, which contain password hashes for all domain users. Attackers leveraging these utilities can perform offline password cracking, obtain LSA secrets, or inject new objects into the Active Directory database. These actions can lead to massive data exfiltration, persistent unauthorized access, and complete degradation of the identity infrastructure integrity.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for PowerShell Script Block executions involving DSInternals-specific cmdlets. Prioritize alerts triggered by service accounts or unusual workstation sources. Ensure that "Script Block Logging" is enabled and correctly forwarded to your centralized logging platform.

## Affected OS

- Windows
