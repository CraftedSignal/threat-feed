---
title: Detection of Unauthorized PowerShell PFX Certificate Export
slug: 2026-10-powershell-cert-export
description: Adversaries leverage the Export-PfxCertificate PowerShell cmdlet to exfiltrate sensitive certificates from the Windows Certificate Store, enabling credential theft and impersonation.
date: "2026-10-12T18:18:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - collection
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Adversaries may abuse this cmdlet to export and exfiltrate sensitive certificates from the Windows Certificate Store, facilitating credential theft.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
    evidence: Monitoring this behavior is crucial for identifying potential certificate theft, which can lead to unauthorized access and impersonation attacks.
    confidence_band: high
rules:
  - title: Detect Export-PfxCertificate PowerShell Cmdlet
    description: Detects the use of the Export-PfxCertificate cmdlet which may indicate an attempt to exfiltrate certificates from the Windows Certificate Store.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - credential_access
    techniques:
      - T1552.004
      - T1649
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
    - action: Enable PowerShell Script Block Logging across Windows environment
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into cmdlet execution
  hunt_leads:
    - lead: Search 4104 logs for export-pfxcertificate
      technique_id: T1552.004
      data_needed:
        - EventID 4104
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Source explicitly identifies 4104 as the data source
  mitigation_plan:
    - priority: medium_term
      action: Restrict local administrative rights to prevent unauthorized certificate store access
      owner: IT Operations
      addresses: T1552.004
      evidence: Preventing unauthorized access limits the impact of certificate theft
---

The use of the PowerShell cmdlet `Export-PfxCertificate` presents a significant security risk when observed in production environments. Threat actors utilize this native functionality to extract certificates along with their private keys from the Windows Certificate Store. This activity is frequently associated with credential access and collection tactics, enabling attackers to bypass secure communication protocols, perform unauthorized authentication, and escalate privileges. Monitoring for this behavior is essential for identifying early signs of certificate theft that could lead to widespread environment compromise or long-term persistence through identity-based attacks. Defenders should focus on PowerShell Script Block Logging (EventID 4104) to capture the execution of this specific cmdlet.

## Attack Chain

1. Attacker gains initial access or code execution on the target Windows endpoint.
2. Attacker explores the local Windows Certificate Store to identify high-value certificates (e.g., code signing or authentication certificates).
3. Attacker uses PowerShell to interact with the PKI module.
4. Attacker executes `Export-PfxCertificate` to export the target certificate and associated private key to a file on disk.
5. The command execution triggers a PowerShell Script Block (Event ID 4104) containing the cmdlet string.
6. Attacker exfiltrates the exported .pfx file to an external, attacker-controlled server.
7. Attacker uses the stolen certificate to perform man-in-the-middle attacks or impersonate legitimate identities.

## Impact

Successful exploitation allows attackers to compromise encrypted communications, authenticate as legitimate users, and potentially gain elevated access to internal systems. While the technique is often used by targeted threat actors, the impact is severe if production or administrative certificates are successfully exfiltrated, leading to a complete compromise of the identity layer within the targeted network.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) on all Windows endpoints to ensure visibility into cmdlet execution.
* Deploy the detection rule below to your SIEM to monitor for the use of `Export-PfxCertificate`.
* Review administrative scripts that legitimately use this cmdlet and establish a process for tuning the detection to reduce noise from authorized maintenance activity.
