---
title: Detection of MSI Installation via PowerShell WMI Win32_Product
slug: 2026-09-wmi-win32-product-msi
description: This brief documents a detection method for the use of PowerShell to trigger MSI installations through the WMI Win32_Product class, a technique often utilized for software deployment or unauthorized persistence.
date: "2026-09-03T13:45:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - powershell
  - wmi
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The use of Win32_Product to install MSI files is a known technique for proxying execution to avoid direct detection.
    confidence_band: high
rules:
  - title: Detect PowerShell WMI Win32_Product MSI Installation
    description: Detects the execution of an MSI file using PowerShell and the WMI Win32_Product class method
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into WMI method calls.
  hunt_leads:
    - lead: Search for instances of Invoke-CimMethod targeting Win32_Product
      technique_id: T1218.007
      data_needed:
        - PowerShell Script Block logs (Event ID 4104)
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Technique uses standard administrative commands that are visible in script block logs.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict Application Control or AppLocker policies to prevent execution of unauthorized MSIs
      owner: IT Operations
      addresses: Technique T1218.007
      evidence: AppLocker provides a fallback defense against unauthorized MSI execution.
---

The Win32_Product WMI class in Windows is designed to query installed MSI packages. However, it also exposes a method that allows for the remote or local installation of new MSI files. Adversaries leverage this functionality to execute malicious MSI files as an alternative to standard installation binaries. By invoking this method via PowerShell's `Invoke-CimMethod` cmdlet, attackers can maintain stealth by avoiding common process-creation logs associated with `msiexec.exe` execution directly via the command line. Defenders should monitor Script Block Logging to capture the specific WMI method calls that instantiate the installation process.

## Impact

Successful abuse of this technique can lead to silent installation of malicious software, persistence via backdoors disguised as legitimate applications, and potential system compromise. If used for lateral movement, this technique allows an adversary to install software across multiple remote endpoints if they possess appropriate WMI credentials.

## Recommendation

Deploy the following Sigma rule to monitor for suspicious MSI installation commands via WMI. Ensure PowerShell Script Block Logging (Event ID 4104) is enabled and forwarded to the SIEM.

- Enable PowerShell Script Block Logging via Group Policy (Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging).
- Review all detected instances to identify unauthorized software installations or potential persistence mechanisms.
