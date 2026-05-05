---
title: Cisco Secure Endpoint Tampering via SFC Utility
slug: 2024-01-03-cisco-secure-endpoint-tampering
description: An attacker attempts to disable the Immunet Protect service of Cisco Secure Endpoint by leveraging the `sfc.exe` utility with the `-k` parameter, potentially blinding the EDR for further compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - endpoint
  - cisco
vendors:
  - Cisco
products:
  - Secure Endpoint
  - Immunet Protect
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.cisco.com/c/en/us/support/docs/security/amp-endpoints/213690-amp-for-endpoint-command-line-switches.html
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_cisco_secure_endpoint_stop_immunet_service_via_sfc.yml
rules:
  - title: Windows Cisco Secure Endpoint Stop Immunet Service Via Sfc
    description: Detects the execution of sfc.exe with the -k parameter to stop the Immunet service.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious SFC.exe Execution from Non-Standard Path
    description: Detects sfc.exe executing from a non-standard path.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the potential tampering of Cisco Secure Endpoint's Immunet Protect service. The technique involves leveraging the `sfc.exe` utility, a legitimate component within the Cisco Secure Endpoint installation, to stop the Immunet service. The abuse of `sfc.exe` with the `-k` parameter is a critical indicator, as it's not a typical administrative function and signals a deliberate attempt to weaken endpoint defenses. This activity matters because a compromised endpoint with disabled security measures can lead to further exploitation, lateral movement, and data exfiltration. The technique was observed in the Splunk security content and can be detected via endpoint telemetry.

## Attack Chain

1. Initial access is assumed to have been achieved via other means (e.g., phishing, exploit).
2. The attacker gains a foothold on the targeted endpoint.
3. The attacker identifies the presence of Cisco Secure Endpoint and Immunet Protect.
4. The attacker executes `sfc.exe` with the `-k` parameter, specifically targeting the Immunet Protect service.
5. The command execution stops the Immunet Protect service, effectively disabling real-time protection.
6. The attacker leverages the weakened security posture to deploy malware or execute malicious scripts.
7. The attacker attempts lateral movement to other systems on the network.
8. The attacker achieves their objective (e.g., data theft, ransomware deployment) without detection.

## Impact

A successful attack can lead to the disabling of real-time protection offered by Immunet Protect, a component of Cisco Secure Endpoint. This allows attackers to bypass endpoint security measures and execute malicious code without detection. The impact may include data breaches, ransomware infections, and further compromise of systems within the network. The number of victims depends on the scope of the attacker's lateral movement after initial compromise.

## Recommendation

*   Deploy the Sigma rule "Windows Cisco Secure Endpoint Stop Immunet Service Via Sfc" to your SIEM to detect the execution of `sfc.exe` with the `-k` parameter (see rules section).
*   Enable Sysmon process creation logging to capture command-line arguments for process monitoring and detection (see logsource).
*   Investigate any instances of `sfc.exe` execution with the `-k` parameter, especially when originating from unusual parent processes or locations.
*   Implement strict process whitelisting to prevent unauthorized execution of `sfc.exe` from non-standard paths.
*   Monitor for unusual process behavior following the execution of `sfc.exe`, such as the creation of suspicious files or network connections.
