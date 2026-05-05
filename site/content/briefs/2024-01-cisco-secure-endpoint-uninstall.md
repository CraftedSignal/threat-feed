---
title: Cisco Secure Endpoint Uninstallation via SFC Utility
slug: 2024-01-cisco-secure-endpoint-uninstall
description: The sfc.exe utility is used with the "-u" parameter to uninstall Cisco Secure Endpoint components, potentially disabling endpoint protection and facilitating further exploitation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - security-solution-tampering
  - endpoint
  - windows
vendors:
  - Cisco
  - Splunk
products:
  - Secure Endpoint
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
references:
  - https://www.cisco.com/c/en/us/support/docs/security/amp-endpoints/213690-amp-for-endpoint-command-line-switches.html
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_cisco_secure_endpoint_uninstall_immunet_service_via_sfc.yml
rules:
  - title: Detect Cisco Secure Endpoint Uninstall via SFC
    description: Detects the execution of sfc.exe with the '-u' parameter, potentially indicating an attempt to uninstall Cisco Secure Endpoint components.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Cisco Secure Endpoint Uninstall via SFC (Parent Process)
    description: Detects the execution of sfc.exe with the '-u' parameter with suspicious parent process, potentially indicating an attempt to uninstall Cisco Secure Endpoint components.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The System File Checker (sfc.exe) is a Windows utility used to scan and restore corrupted system files. However, it can also be abused to uninstall components of security software. This detection focuses on the use of `sfc.exe` with the `-u` parameter, a legitimate but potentially malicious use case related to Cisco Secure Endpoint. An attacker might leverage this command to remove or disable parts of the endpoint protection suite, creating an opportunity to deploy malware, exfiltrate data, or perform other malicious activities without immediate detection. This type of tampering aims to weaken defenses before a more significant attack. This activity is often part of a broader effort to disable security mechanisms to avoid detection.

## Attack Chain

1.  Initial access to the system is achieved through unspecified means (e.g., compromised credentials, software vulnerability).
2.  The attacker gains elevated privileges on the compromised system.
3.  The attacker executes `sfc.exe` with the `-u` parameter to attempt to uninstall the Cisco Secure Endpoint Immunet service.
4.  `sfc.exe` attempts to uninstall the specified Cisco Secure Endpoint component.
5.  If successful, the targeted component of Cisco Secure Endpoint is disabled or removed from the system.
6.  The attacker leverages the weakened state of the endpoint security to deploy malware or perform other malicious activities.
7.  The attacker attempts to move laterally within the network.
8.  The attacker exfiltrates sensitive data from the compromised system or network.

## Impact

Successful execution of this attack can lead to the complete removal or disabling of Cisco Secure Endpoint protection on a targeted system. This leaves the system vulnerable to malware infection, data exfiltration, and other malicious activities. The impact can range from individual system compromise to a widespread breach affecting numerous endpoints within an organization, leading to significant data loss and operational disruption.

## Recommendation

*   Deploy the Sigma rule `Detect Cisco Secure Endpoint Uninstall via SFC` to your SIEM and tune for your environment.
*   Monitor process execution logs for instances of `sfc.exe` being used with the `-u` parameter, as highlighted in the Sigma rule and the `search` field in the provided source.
*   Investigate any detected instances of this behavior to determine if they are legitimate or malicious, per the `known_false_positives` from the original source.
*   Implement strict access controls to limit the ability of users to execute system utilities like `sfc.exe`.
*   Enable Sysmon process-creation logging to activate the rules above.
