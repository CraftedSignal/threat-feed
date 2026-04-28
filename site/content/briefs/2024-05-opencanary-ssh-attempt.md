---
title: OpenCanary SSH Connection Attempt
slug: 2024-05-opencanary-ssh-attempt
description: An SSH connection attempt to an OpenCanary node indicates a potential adversary probing for vulnerable services or attempting unauthorized access within a network.
date: "2024-05-08T14:30:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - honeypot
  - ssh
  - reconnaissance
vendors:
  - Thinkst
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
  - title: OpenCanary - SSH New Connection Attempt
    description: Detects instances where an SSH service on an OpenCanary node has had a connection attempt.
    platform: sigma
    severity: high
    tactics:
      - initial-access
    techniques:
      - T1133
    data_sources:
      - application
      - opencanary
  - title: OpenCanary - Multiple SSH connection attempts from single IP
    description: Detects multiple SSH connection attempts to an OpenCanary node from a single IP address within a short time frame, indicating potential brute-force activity.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1110.001
    data_sources:
      - application
      - opencanary
rules_count: 2
---

The OpenCanary SSH Connection Attempt alert signifies that an SSH service on a deployed OpenCanary node has received a connection attempt. OpenCanary is a low-interaction honeypot designed to detect reconnaissance and lateral movement activities within a network. This event, logged as logtype 4000 by default, suggests that an attacker is actively scanning for or attempting to exploit SSH services. This alert is crucial for defenders because OpenCanary nodes are deliberately placed to attract malicious activity, meaning any interaction is highly suspicious. The alert helps identify potential breaches early, allowing security teams to respond quickly. The configuration of services monitored by OpenCanary is detailed in the project's documentation.

## Attack Chain

1.  Initial Reconnaissance: The attacker conducts network scanning using tools like Nmap or Masscan to identify open ports and services, including SSH (port 22).
2.  Target Identification: The attacker identifies the OpenCanary node, mistaking it for a legitimate SSH server, due to its exposed SSH port.
3.  Connection Attempt: The attacker attempts to establish an SSH connection to the OpenCanary node using a tool like `ssh` or a custom script.
4.  Authentication Probe: The attacker might attempt to authenticate using default credentials, common usernames and passwords, or brute-force techniques.
5.  Credential Compromise (Simulated): The OpenCanary node logs the failed or successful (simulated) login attempt, triggering the alert. OpenCanary may simulate a successful login for further interaction logging.
6.  Lateral Movement (Attempted): If the attacker believes they have successfully authenticated, they may attempt lateral movement to other systems within the network.
7.  Privilege Escalation (Attempted): The attacker could attempt to escalate privileges on the "compromised" system (OpenCanary) to gain further access.
8.  Data Exfiltration/System Damage (Prevented): Because it's a honeypot, OpenCanary prevents actual data exfiltration or system damage but logs all attempted actions for analysis.

## Impact

An SSH connection attempt on an OpenCanary node, while not directly causing damage, indicates active reconnaissance or attempted unauthorized access within the network. The number of alerts generated can highlight the frequency of malicious scans targeting SSH services. Successful exploitation (simulated on the honeypot) could lead to lateral movement, privilege escalation, and data exfiltration if the attacker were to compromise a real system. This activity is valuable for understanding attacker behavior and improving overall security posture.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect SSH connection attempts to OpenCanary nodes, focusing on `logtype: 4000`.
*   Review OpenCanary logs in conjunction with other security logs (firewall, endpoint) to correlate the SSH attempts with other suspicious activities.
*   Investigate the source IP addresses from which SSH connection attempts originate to identify potential threat actors.
*   Consult the OpenCanary documentation to ensure proper configuration of the SSH service and logging capabilities.
*   Use network segmentation to limit the potential impact of a successful breach, even if only simulated on the OpenCanary node.
