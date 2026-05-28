---
title: Cisco Privileged Account Creation with Suspicious SSH Activity
slug: 2026-05-cisco-priv-account-ssh
description: This analytic detects a correlation between privileged account creation on Cisco IOS devices and subsequent inbound SSH connections to non-standard ports or sshd_operns, indicating persistence establishment following initial compromise.
date: "2026-05-28T17:47:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - network
  - persistence
  - initial-access
vendors:
  - Cisco
  - Splunk
products:
  - IOS
  - Secure Firewall Threat Defense
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1021.004
    technique_name: 'Remote Services: SSH'
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a
rules:
  - title: Detect Cisco IOS Suspicious Privileged Account Creation
    description: Detects suspicious privileged account creation on Cisco IOS devices.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136
    data_sources:
      - network
      - cisco
  - title: Detect Cisco Secure Firewall SSH Connection to Non-Standard Port
    description: Detects SSH connections to non-standard ports on Cisco Secure Firewall.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1021.004
    data_sources:
      - firewall
      - cisco
  - title: Detect Cisco Secure Firewall SSH Connection to sshd_operns
    description: Detects SSH connections triggering the sshd_operns signature on Cisco Secure Firewall.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1021.004
    data_sources:
      - firewall
      - cisco
rules_count: 3
---

This detection identifies suspicious activity on Cisco IOS devices and Cisco Secure Firewalls that could indicate a compromised device. The alert focuses on the creation of privileged accounts on Cisco IOS devices followed by unusual SSH activity. Unusual SSH activity is defined as connections to non-standard ports or connections using the 'sshd_operns' signature. The combination of these two events on the same network device within a short timeframe is a strong indicator of an attacker attempting to establish persistence after gaining initial access. This behavior is often observed in post-exploitation scenarios where attackers aim to maintain unauthorized access to compromised systems. This detection helps security teams identify and respond to potential breaches early in the attack lifecycle, preventing further damage.

## Attack Chain

1. An attacker gains initial access to a Cisco IOS device, potentially through exploiting a vulnerability or using compromised credentials.
2. The attacker creates a new privileged account on the Cisco IOS device.
3. The system logs this suspicious privileged account creation, triggering the "Cisco IOS Suspicious Privileged Account Creation" detection.
4. The attacker attempts to establish persistence by enabling SSH access for the newly created account.
5. The attacker connects to the Cisco IOS device via SSH, potentially using a non-standard port or triggering the 'sshd_operns' signature.
6. The Cisco Secure Firewall logs the SSH connection to a non-standard port or the 'sshd_operns' signature, triggering the "Cisco Secure Firewall - SSH Connection to Non-Standard Port" or "Cisco Secure Firewall - SSH Connection to sshd_operns" detection.
7. Splunk correlates the privileged account creation event with the suspicious SSH activity, generating an alert.
8. The attacker uses the newly created privileged account and established SSH access to perform malicious activities within the network.

## Impact

A successful attack can lead to unauthorized access to critical network devices, allowing attackers to modify configurations, intercept network traffic, or further compromise other systems on the network. This can result in data breaches, service disruptions, and significant financial losses. The referenced CISA advisory AA25-239A describes similar tactics.

## Recommendation

*   Enable the "Cisco IOS Suspicious Privileged Account Creation", "Cisco Secure Firewall - SSH Connection to sshd_operns", and "Cisco Secure Firewall - SSH Connection to Non-Standard Port" detections in your Splunk environment as required by the correlation search.
*   Ensure that Cisco IOS logs (sourcetype "cisco:ios") and Cisco Secure Firewall Threat Defense Intrusion Event logs are being ingested into Splunk.
*   Deploy the correlation search and associated filters in your Splunk environment.
*   Investigate any triggered alerts to determine the extent of the compromise and take appropriate remediation steps.
*   Tune the `cisco_privileged_account_creation_with_suspicious_ssh_activity_filter` macro to reduce false positives in your environment.
