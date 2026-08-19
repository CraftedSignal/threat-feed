---
title: Detection of Adversarial Reconnaissance of Windows Uninstall Registry Keys
slug: 2026-08-windows-uninstall-registry-recon
description: Adversaries and information-stealing malware, including RedLine and StealC, query Windows registry keys in 'Microsoft\Windows\CurrentVersion\Uninstall\' to perform software enumeration for target selection.
date: "2026-08-19T22:29:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1012
    technique_name: Query Registry
    evidence: The following analytic detects an access request on the uninstall registry key.
    confidence_band: high
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_query_registry_uninstall_program_list.yml
rules:
  - title: Detect Access to Uninstall Registry Keys
    description: Detects processes attempting to read the registry keys containing installed program information, a common reconnaissance tactic used by infostealers.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1012
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
    - action: Enable Audit Object Access for registry keys
      owner: IT Operations
      due: 72h
      evidence: Required for Event ID 4663 collection.
  hunt_leads:
    - lead: Identify processes accessing registry keys in the Uninstall path.
      technique_id: T1012
      data_needed:
        - Windows Security Log
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Known technique used by RedLine/StealC.
---

Adversaries frequently employ reconnaissance techniques to map the host environment following initial compromise. A common, low-noise method for gathering system information involves querying the Windows registry, specifically keys associated with installed applications. The path 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' (and its HKCU counterpart) contains metadata about installed software, which attackers use to identify security products, enterprise software, or vulnerable versions of applications to facilitate follow-on exploitation.

This activity is heavily utilized by information-stealing malware families, including RedLine Stealer, StealC, Meduza, and Vidar. These threats query these registry locations to build an inventory of the host, which is then exfiltrated or used to tailor the malware's malicious payload. Defenders can identify this reconnaissance by monitoring for sensitive object access events within the Windows Security log. This detection is particularly effective for catching automated enumeration scripts and malware before they proceed to exfiltration or credential harvesting stages.

## Attack Chain

1. Initial access is gained on the target host, typically via phishing or exploitation of external-facing services.
2. Malicious payload or stager is executed with local user or administrative privileges.
3. The malware performs system survey to identify installed security controls and software packages.
4. The malware attempts to open a handle to registry subkeys under 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'.
5. Windows Security Event ID 4663 is generated when the process requests access to these objects, provided Object Access Auditing is enabled.
6. The malware iterates through subkeys to read the 'DisplayName' and 'DisplayVersion' values for each installed application.
7. Enumerated information is exfiltrated to the C2 server or used to drop specific malicious modules.

## Impact

Successful execution of this reconnaissance phase allows an attacker to build an accurate profile of the target environment. This aids in identifying potential targets for privilege escalation, identifying installed security software to evade, and ensuring the environment matches the requirements for further malicious activity. While the action itself is a discovery tactic, it serves as a high-confidence indicator of active post-compromise activity by infostealers.

## Recommendation

1. Enable "Audit Object Access" for registry keys in the Windows Security Policy to ensure Event ID 4663 is logged.
2. Deploy the provided Sigma rule to monitor for suspicious process access to the 'Uninstall' registry keys.
3. Tune the detection to filter out legitimate software installers or update managers that legitimately query these keys during maintenance.
4. Review endpoints that trigger this alert for additional indicators of infostealer activity, such as suspicious file drops or encrypted network traffic.
