---
title: FortiGate - New Administrator Account Created
slug: 2026-07-fortigate-new-admin-account
description: This brief describes how to detect the creation of new administrator accounts on Fortinet FortiGate firewalls, a behavior often used by attackers for persistence (ATT&CK T1136.001) or to maintain unauthorized access after initial compromise.
date: "2026-07-03T13:52:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.persistence
  - attack.t1136.001
  - network-device
  - fortinet
vendors:
  - Fortinet
products:
  - FortiGate Firewall
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Detects the creation of an administrator account on a Fortinet FortiGate Firewall.
    confidence_band: high
references:
  - https://www.fortiguard.com/psirt/FG-IR-24-535
  - https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
  - https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/390485493/config-system-admin
  - https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr
rules:
  - title: FortiGate - New Administrator Account Created
    description: Detects the creation of an administrator account on a Fortinet FortiGate Firewall, which could indicate unauthorized persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136.001
    data_sources:
      - fortigate
      - event
rules_count: 1
---

This detection brief focuses on identifying the creation of new administrator accounts on Fortinet FortiGate firewall devices. Attackers frequently use the creation of new user accounts, particularly those with administrative privileges, as a post-exploitation technique to establish persistence and ensure continued access to compromised environments. While legitimate administrator accounts are routinely created for operational purposes, an unauthorized account creation can signify a successful breach, an insider threat, or the escalation of privileges within the network. This alert is crucial for defenders to identify suspicious activity that could lead to unauthorized configuration changes, data exfiltration, or further network compromise. The provided Sigma rule leverages FortiGate's event logs to pinpoint these critical configuration changes.

## Attack Chain

[The source material for this brief focuses on a specific detection capability rather than detailing a full attack chain. Therefore, a complete attack chain cannot be constructed.]

## Impact

If an unauthorized administrator account is successfully created on a FortiGate firewall, attackers gain full control over the network's security perimeter. This can lead to a wide range of devastating impacts, including the disablement of security features (e.g., VPNs, IPS, antivirus), creation of rogue network access rules, redirection of traffic, exfiltration of sensitive data, or complete disruption of network services. Such an event provides attackers with a stealthy and persistent foothold, making detection and remediation significantly more challenging and potentially leading to extensive financial and reputational damage.

## Recommendation

*   Deploy the Sigma rule "FortiGate - New Administrator Account Created" to your SIEM and tune for your environment to detect unauthorized account creations.
*   Ensure FortiGate event logging is properly configured and integrated with your SIEM to capture `cfgpath: 'system.admin'` events.
*   Regularly review FortiGate access logs for unusual login patterns, especially from newly created accounts.
*   Implement multi-factor authentication for all administrative accounts on FortiGate devices.
