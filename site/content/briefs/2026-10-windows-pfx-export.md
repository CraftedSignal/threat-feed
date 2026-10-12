---
title: Detection of Unauthorized Certificate Export via PowerShell
slug: 2026-10-windows-pfx-export
description: Adversaries may use the PowerShell cmdlet Export-PfxCertificate to exfiltrate authentication certificates from the Windows Certificate Store, enabling identity impersonation and data decryption.
date: "2026-10-12T18:22:50Z"
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
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
    evidence: Adversaries may leverage this technique to exfiltrate authentication certificates, enabling them to impersonate users or decrypt sensitive traffic/data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The following analytic detects the use of the PowerShell cmdlet export-pfxcertificate on the command line.
    confidence_band: high
rules:
  - title: Detect Unauthorized Export-PfxCertificate Usage
    description: Detects the use of the PowerShell cmdlet Export-PfxCertificate, which may indicate an attempt to exfiltrate authentication certificates.
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
    - action: Deploy Sigma rule to detect suspicious Export-PfxCertificate usage
      owner: Detection Engineering
      due: 48h
      evidence: Source document identifies this as a primary detection technique
  hunt_leads:
    - lead: Search for historical use of Export-PfxCertificate in command-line telemetry
      technique_id: T1649
      data_needed:
        - Process creation logs with full command-line arguments
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Tooling usage history can reveal previous unauthorized exports
---

This threat brief focuses on the potential abuse of the Windows `Export-PfxCertificate` PowerShell cmdlet for malicious credential access. While legitimate administrators use this command to manage certificates, adversaries often abuse it to extract private keys and certificates from the local Windows Certificate Store. By obtaining these files, an attacker can impersonate legitimate users, bypass authentication controls, or decrypt sensitive network traffic and encrypted data. The technique, identified as T1649, is frequently observed in post-exploitation scenarios where the attacker has already achieved sufficient privileges to interact with the certificate store. Defenders should monitor for suspicious execution patterns of this cmdlet, particularly when initiated by non-administrative processes or unusual parent processes.

## Attack Chain

1. Attacker gains initial access to the target Windows endpoint.
2. Attacker performs local reconnaissance to identify stored certificates.
3. Attacker uses PowerShell to invoke the `Export-PfxCertificate` cmdlet.
4. The command targets the Local Machine or Current User certificate store.
5. The certificate and associated private key are exported to a staging file (e.g., .pfx file).
6. The exported file is exfiltrated from the system via C2 channels or other exfiltration methods.
7. Attacker uses the stolen certificate for lateral movement or authentication bypass.

## Impact

Successful execution of this technique can result in a significant security breach, including the loss of authentication integrity, unauthorized access to secure services, and the exposure of sensitive encrypted information. The scope of impact is highly dependent on the privileges associated with the stolen certificate, potentially affecting the entire organization if high-privilege or machine-wide certificates are compromised.

## Recommendation

* Deploy the Sigma rule provided below to identify suspicious use of `Export-PfxCertificate` in your environment.
* Baseline legitimate certificate management activities to reduce noise from automated utilities and administrative scripts.
* Implement strict execution policies for PowerShell and monitor for execution of sensitive cmdlets by unauthorized users.
* Enable Sysmon process-creation logging (Event ID 1) to capture full command-line arguments required for detection.
