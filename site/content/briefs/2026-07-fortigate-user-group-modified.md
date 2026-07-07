---
title: FortiGate User Group Modification Detected
slug: 2026-07-fortigate-user-group-modified
description: An attacker with initial access to a Fortinet FortiGate firewall may modify existing user groups to establish persistence or elevate privileges, potentially granting unauthorized VPN access to internal networks.
date: "2026-07-03T13:56:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - fortinet
  - firewall
  - persistence
  - privilege-escalation
vendors:
  - Fortinet
products:
  - FortiGate
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Detects the modification of a user group on a Fortinet FortiGate Firewall. The group could be used to grant VPN access to a network.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Detects the modification of a user group on a Fortinet FortiGate Firewall. The group could be used to grant VPN access to a network.
    confidence_band: high
references:
  - https://www.fortiguard.com/psirt/FG-IR-24-535
  - https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
  - https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/328136827/config-user-group
  - https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr
  - https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_user_group_modified.yml
rules:
  - title: FortiGate - User Group Modified
    description: Detects the modification of a user group on a Fortinet FortiGate Firewall, potentially for unauthorized access or persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - fortigate
      - event
rules_count: 1
---

This brief highlights the detection of suspicious modifications to user groups on Fortinet FortiGate firewall devices. While seemingly benign, unauthorized alteration of user groups is a critical post-compromise activity that threat actors leverage to solidify their foothold within a network. By editing user groups, attackers can grant themselves or other compromised accounts elevated privileges, such as unrestricted VPN access, access to sensitive network segments, or bypass existing security controls. This action serves as a strong indicator of persistence or privilege escalation attempts, enabling adversaries to move laterally or maintain access even if their initial entry point is remediated. Organizations utilizing FortiGate devices should monitor for these configuration changes diligently to identify and respond to potential breaches. This behavior is a generic post-exploitation technique and is not tied to a specific campaign or CVE, but rather a common tactic employed by various threat actors once device access is achieved.

## Impact

Successful unauthorized modification of FortiGate user groups can lead to severe consequences, including significant network compromise and data breaches. If an attacker gains unauthorized VPN access, they can bypass network segmentation, access sensitive internal resources, exfiltrate data, or deploy further malicious payloads like ransomware. The impact can extend to complete network control, loss of critical business data, and disruption of operations. The exact number of potential victims or targeted sectors is not specified in the provided intelligence, as this is a detection for a general malicious behavior rather than a specific campaign.

## Recommendation

Prioritized, concrete actions for detection engineering teams.
- Deploy the Sigma rule "FortiGate - User Group Modified" to your SIEM and tune for your environment, paying close attention to administrative accounts performing these changes.
- Review FortiGate log sources regularly for configuration changes, specifically for the `event` service logs where `cfgpath` is 'user.group' and `action` is 'Edit'.
- Implement multi-factor authentication (MFA) for all administrative interfaces and VPN access on FortiGate devices to mitigate unauthorized access even if credentials are compromised.
- Conduct periodic audits of FortiGate user groups and permissions to ensure only authorized changes have been made and to identify any lingering unauthorized configurations.
