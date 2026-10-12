---
title: Monitoring Unauthorized Export of Windows Store Certificates
slug: 2026-10-windows-certificate-export
description: Detection of unauthorized certificate exports from the Windows Certificate Store via event ID 1007 to identify potential credential theft and unauthorized access attempts.
date: "2026-10-12T18:07:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - defense-evasion
  - windows
  - certificate-services
vendors:
  - Microsoft
products:
  - Windows Certificate Store
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The following analytic detects the export of a certificate from the Windows Certificate Store.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
    evidence: Monitoring certificate exports is crucial as certificates can be used for authentication to VPNs or private resources.
    confidence_band: high
rules:
  - title: Detect Windows Certificate Export
    description: Detects the export of a certificate from the Windows Certificate Store using Event ID 1007
    platform: sigma
    severity: medium
    tactics:
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
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable Microsoft-Windows-CertificateServicesClient-Lifecycle logs
      owner: IT Operations
      due: 48h
      evidence: Required for Event ID 1007 visibility
  hunt_leads:
    - lead: Identify all instances of Event ID 1007 to establish a baseline of normal export activity
      technique_id: T1649
      data_needed:
        - EventID 1007 logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: False positives may be generated based on an automated process
---

This detection brief focuses on identifying the export of certificates from the Windows Certificate Store, an activity that often indicates credential theft or reconnaissance by an adversary. Attackers frequently target private keys and associated certificates to facilitate unauthorized access to VPNs, encrypted communications, or other high-privilege resources. Defenders can monitor for this activity by tracking the 'Microsoft-Windows-CertificateServicesClient-Lifecycle' operational log channel, specifically Event ID 1007. Because legitimate system services or administrative tasks may occasionally trigger this event, security teams should focus on baselining authorized export activity before implementing blocking or high-fidelity alerts.

## Impact

Successful exfiltration of certificates allows adversaries to perform man-in-the-middle attacks, impersonate users or services for authentication, and decrypt sensitive traffic. This technique is often used in lateral movement and persistence scenarios to maintain access to corporate VPNs or internal private resources, potentially leading to widespread unauthorized data access.

## Recommendation

* Enable logging for 'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational' and 'Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational' channels.
* Deploy the provided Sigma rule to your SIEM to monitor for Event ID 1007.
* Baseline the environment to identify legitimate automated processes that export certificates and add them to an allowlist to minimize false positives.
* Investigate endpoints generating multiple certificate export events in a short period, as this may indicate an interactive attacker performing bulk exfiltration.
