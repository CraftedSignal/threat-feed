---
title: FortiGate VPN SSL Settings Modified
slug: 2026-07-fortigate-vpn-ssl-settings-modified
description: Detection of FortiGate VPN SSL settings modification, such as authentication rules, linked to observed exploitation campaigns (e.g., CVE-2024-535), which threat actors leverage for persistence and unauthorized access after initial compromise.
date: "2026-07-03T13:57:02Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - persistence
  - initial-access
  - network-device
  - fortigate
vendors:
  - Fortinet
products:
  - FortiGate
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: This behavior was observed in pair with the addition of a VPN SSL Web Portal.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Detects the modification of VPN SSL Settings (for example, the modification of authentication rules). This behavior was observed in pair with the addition of a VPN SSL Web Portal.
    confidence_band: high
references:
  - https://www.fortiguard.com/psirt/FG-IR-24-535
  - https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
  - https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/114404382/config-vpn-ssl-settings
  - https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44546/44546-logid-event-config-attr
rules:
  - title: FortiGate - VPN SSL Settings Modified
    description: Detects the modification of VPN SSL Settings (for example, the modification of authentication rules) on FortiGate devices, a behavior observed in pair with the addition of a VPN SSL Web Portal following compromise.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1133
    data_sources:
      - fortigate
      - event
rules_count: 1
---

This threat brief focuses on the detection of modifications to FortiGate VPN SSL settings, a behavior observed in conjunction with the addition of VPN SSL Web Portals. While such changes can be legitimate for administrative purposes, they are also a common post-exploitation tactic by threat actors seeking to establish persistence and maintain unauthorized access to compromised FortiGate devices and, subsequently, the internal network. The FortiGuard PSIRT advisory FG-IR-24-535, a Remote Code Execution (RCE) vulnerability in FortiGate SSL VPN, confirms active exploitation in the wild, suggesting that these configuration changes are often a follow-up action to successful initial compromise via such vulnerabilities. Defenders should be vigilant for these modifications, as they indicate potential adversarial control over network perimeter devices.

## Attack Chain

1.  **Initial Access**: Threat actors exploit vulnerabilities (e.g., FortiGate SSL VPN RCE like CVE-2024-535) in internet-facing FortiGate appliances.
2.  **Execution**: Upon successful exploitation, the attacker gains remote code execution capabilities on the FortiGate device.
3.  **Persistence/Defense Evasion**: The attacker modifies existing VPN SSL settings, potentially altering authentication rules to weaken security controls or bypass multi-factor authentication.
4.  **Persistence**: The attacker adds a new VPN SSL Web Portal or modifies an existing one to establish a covert or unauthorized access point.
5.  **Credential Access/Lateral Movement**: New administrative accounts may be created or existing ones compromised to ensure ongoing access through the modified VPN infrastructure.
6.  **Access/Impact**: The attacker utilizes the altered VPN access to gain unauthorized entry into the internal corporate network, enabling further reconnaissance, data exfiltration, or deployment of additional malicious payloads.

## Impact

Successful exploitation leading to VPN SSL setting modifications grants threat actors persistent, unauthorized access to an organization's internal network. This can bypass traditional perimeter defenses and lead to significant data breaches, deployment of ransomware, or other destructive activities. The specific RCE vulnerability (FG-IR-24-535) associated with this activity is actively exploited, increasing the likelihood of real-world impact for unpatched systems. Organizations across all sectors relying on FortiGate SSL VPNs are potential targets.

## Recommendation

*   Deploy the Sigma rule "FortiGate - VPN SSL Settings Modified" to your SIEM solution to detect configuration changes.
*   Ensure FortiGate logging is configured to send `event` service logs, specifically `config` events, to your SIEM for correlation with the provided Sigma rule.
*   Regularly review FortiGate VPN SSL settings for unauthorized modifications or newly created web portals, comparing current configurations against known baselines.
*   Patch CVE-2024-535 and any other critical FortiGate SSL VPN vulnerabilities immediately, as exploitation often precedes these configuration changes.
*   Implement strong authentication, including multi-factor authentication (MFA), for all VPN access, and monitor its enforcement.
