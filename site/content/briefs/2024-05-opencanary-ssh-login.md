---
title: OpenCanary SSH Login Attempt Detection
slug: 2024-05-opencanary-ssh-login
description: Detects instances where an SSH service on an OpenCanary node has had a login attempt, indicating potential reconnaissance, privilege escalation, or lateral movement.
date: "2024-05-02T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - honeypot
  - ssh
  - initial-access
vendors:
  - thinkst
products:
  - OpenCanary
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
  - https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52
rules:
  - title: OpenCanary - SSH Login Attempt
    description: Detects instances where an SSH service on an OpenCanary node has had a login attempt.
    platform: sigma
    severity: high
    tactics:
      - initial-access
    techniques:
      - T1133
    data_sources:
      - application
      - opencanary
  - title: OpenCanary - Custom Logtype SSH Login Attempt
    description: Detects instances where an SSH service on an OpenCanary node has had a login attempt, using a custom logtype.
    platform: sigma
    severity: high
    tactics:
      - initial-access
    techniques:
      - T1133
    data_sources:
      - application
      - opencanary
rules_count: 2
---

OpenCanary is a low-interaction honeypot designed to detect attackers on a network. This brief focuses on detecting SSH login attempts on OpenCanary nodes, which are designed to mimic real SSH servers but log any interaction. While the OpenCanary project itself has been around for several years, its integration with modern detection strategies makes it a valuable tool for defenders. An SSH login attempt against an OpenCanary instance signifies that an attacker is actively scanning or attempting to compromise systems within the network. This activity might be part of a broader campaign, including lateral movement, privilege escalation, or data exfiltration. The detection of such attempts allows for timely incident response and mitigation.

## Attack Chain

1.  The attacker gains initial access to the network, possibly through phishing, exploiting a vulnerability, or compromised credentials.
2.  The attacker performs network scanning to identify potential targets, including the OpenCanary node masquerading as a legitimate SSH server.
3.  The attacker attempts to establish an SSH connection to the OpenCanary node, attempting to authenticate using various usernames and passwords.
4.  The OpenCanary service logs the failed SSH login attempt, recording the source IP address and attempted credentials.
5.  Security monitoring tools ingest the OpenCanary logs and trigger an alert based on the detected SSH login attempt.
6.  Security analysts investigate the alert, analyzing the source IP address and other relevant information to determine the scope and severity of the potential breach.

## Impact

A successful SSH login attempt on a real server could lead to complete system compromise, data exfiltration, and disruption of services. While OpenCanary is designed to be a honeypot, detecting login attempts early allows for proactive measures to prevent attackers from reaching critical assets. Identifying the attacker's source IP address and attempted usernames can provide valuable insights into their tactics and objectives, preventing damage.

## Recommendation

*   Deploy the Sigma rule "OpenCanary - SSH Login Attempt" to your SIEM to detect unauthorized SSH login attempts on OpenCanary nodes.
*   Investigate and block any identified malicious source IP addresses from network access using firewall rules.
*   Review OpenCanary configuration to ensure it is deployed in strategically valuable network segments (references: OpenCanary documentation).
*   Correlate OpenCanary alerts with other security events to identify potential broader attack campaigns.
