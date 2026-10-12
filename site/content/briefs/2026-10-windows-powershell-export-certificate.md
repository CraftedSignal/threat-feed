---
title: Detection of Unauthorized PowerShell Certificate Export
slug: 2026-10-windows-powershell-export-certificate
description: Adversaries may leverage the PowerShell cmdlet 'Export-Certificate' to exfiltrate cryptographic material from the Windows Certificate Store, enabling impersonation and decryption of sensitive data.
date: "2026-10-12T18:17:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - power-shell
  - windows
  - certificate-theft
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The following analytic detects the use of the PowerShell Cmdlet 'export-certificate' as it may indicate an adversary attempting to exfiltrate certificates.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
    evidence: Monitoring this behavior is crucial because stolen certificates can be used to impersonate users, decrypt sensitive data, or facilitate further attacks.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_powershell_export_certificate.yml
  - https://learn.microsoft.com/en-us/powershell/module/pki/export-certificate
rules:
  - title: Detect PowerShell Export-Certificate Cmdlet
    description: Detects the use of the PowerShell cmdlet Export-Certificate which may indicate credential exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints.
      owner: IT Operations
      due: 7d
      evidence: Source requirement for analytic implementation.
  hunt_leads:
    - lead: Search for Event ID 4104 containing 'export-certificate' in the last 30 days.
      technique_id: T1649
      data_needed:
        - PowerShell Operational Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Detection rule definition.
  mitigation_plan:
    - priority: medium_term
      action: Restrict local administrative rights to reduce the risk of unauthorized certificate access.
      owner: IT Operations
      addresses: T1649
      evidence: Mitigation of post-compromise privilege escalation.
---

This threat brief focuses on the exploitation of the PowerShell cmdlet 'Export-Certificate' by malicious actors to target the Windows Certificate Store. Adversaries frequently attempt to gain unauthorized access to certificates to facilitate credential theft, impersonate legitimate users, or intercept and decrypt sensitive network communications. This activity is often part of a post-compromise stage where an attacker seeks to establish long-term persistence or gain further access to protected corporate resources. Defenders should monitor for execution of this cmdlet via PowerShell Script Block Logging (Event ID 4104), as its use is rarely required for routine end-user operations. The detection of this command is critical for identifying potential exfiltration of sensitive identity or encryption assets.

## Attack Chain

1. Initial access is established through spearphishing, credential harvesting, or exploitation of a remote service.
2. The attacker performs initial discovery to locate the Windows Certificate Store and determine targets of interest.
3. The attacker gains administrative or elevated local privileges required to access and export certificates.
4. The attacker executes the PowerShell cmdlet 'Export-Certificate' to serialize a certificate into a file.
5. The attacker attempts to bypass file monitoring or exfiltration protections while extracting the exported file.
6. The exported certificate file is staged for exfiltration to external C2 infrastructure.
7. The final objective is the use of the stolen certificate to authenticate as a victim or decrypt intercepted traffic.

## Impact

Successful exfiltration of certificates can lead to severe security incidents, including the bypass of multi-factor authentication, the decryption of encrypted communications, and the assumption of a victim's digital identity across the enterprise. These incidents can compromise the integrity of internal communications and facilitate lateral movement within the network.

## Recommendation

* Deploy PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to ensure visibility into command execution.
* Implement the following detection logic in your SIEM to alert on the usage of 'Export-Certificate' across the environment.
* Audit current administrative scripts to identify and filter out legitimate business processes that require certificate exports, minimizing false positive noise.
