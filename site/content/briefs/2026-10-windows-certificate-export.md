---
title: Abuse of PowerShell Export-Certificate for Credential Theft
slug: 2026-10-windows-certificate-export
description: Adversaries abuse the PowerShell Export-Certificate cmdlet to exfiltrate authentication certificates from the Windows Certificate Store for use in credential theft and man-in-the-middle attacks.
date: "2026-10-12T18:22:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - powershell
  - certificate-theft
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
    evidence: The following analytic detects the use of the PowerShell cmdlet 'export-certificate' executed via the command line, indicating an attempt to export a certificate from the local Windows Certificate Store.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/powershell/module/pki/export-certificate
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1649/T1649.yaml
rules:
  - title: Detect Export-Certificate Execution
    description: Detects the use of the PowerShell cmdlet Export-Certificate, which may indicate an attempt to steal authentication certificates.
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
    - action: Deploy the Sigma detection rule to the SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for T1649 detection
  hunt_leads:
    - lead: Search historical process logs for Export-Certificate command lines
      technique_id: T1649
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: T1649 activity is indicative of credential theft attempts
---

Adversaries are known to leverage built-in Windows administrative utilities to facilitate post-exploitation activities. Specifically, the PowerShell cmdlet 'Export-Certificate' is being utilized to extract authentication certificates from the local Windows Certificate Store. This activity is a precursor to more severe threats, such as user impersonation, the decryption of sensitive network or local traffic, and unauthorized access to protected enterprise systems. By exporting certificates, an attacker gains the ability to effectively clone identities or intercept encrypted communication channels, bypassing traditional authentication mechanisms. Detection engineering teams must focus on monitoring process execution telemetry to identify the use of this cmdlet, which is often executed in the context of broader credential harvesting campaigns. This technique is formally documented under MITRE ATT&CK T1649.

## Impact

Successful exploitation of this technique allows an attacker to obtain valid authentication material from compromised hosts. This grants them the ability to impersonate legitimate users, potentially leading to unauthorized access to internal services, data exfiltration, or the decryption of encrypted traffic. The impact is elevated in environments relying heavily on certificate-based authentication or PKI infrastructure.

## Recommendation

* Deploy the provided Sigma rule to detect suspicious process execution involving 'Export-Certificate'.
* Enable Sysmon Event ID 1 or Windows Event ID 4688 to capture full command-line arguments for all PowerShell executions.
* Filter common administrative tools or legitimate management scripts that utilize certificate export functions to reduce false positives.
* Monitor for unusual parent-child process relationships, such as web servers or office applications spawning PowerShell to execute certificate management commands.
