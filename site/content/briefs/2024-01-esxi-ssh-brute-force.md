---
title: ESXi SSH Brute-Force Attack Attempt
slug: 2024-01-esxi-ssh-brute-force
description: Detection of a potential brute-force attack against an ESXi host via SSH by monitoring for a high number of failed login attempts within a short time frame, indicating an attacker attempting to gain unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esxi
  - ssh
  - brute-force
  - credential-access
  - vmware
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_ssh_brute_force.yml
rules:
  - title: ESXi SSH Brute Force Detection
    description: Detects potential SSH brute-force attacks against ESXi hosts by monitoring for a high number of failed login attempts from the same source IP address within a short time frame.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - syslog
      - vmware
  - title: ESXi SSH Successful Login After Failed Attempts
    description: Detects successful SSH login after multiple failed attempts, which may indicate successful credential stuffing or brute forcing.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1110
    data_sources:
      - syslog
      - vmware
rules_count: 2
---

This detection identifies potential SSH brute-force attacks targeting VMware ESXi hosts. The attack is characterized by a high volume of failed SSH login attempts originating from one or more source IP addresses against a specific ESXi host within a short timeframe. The detection leverages ESXi syslog data to identify these patterns. Successful brute-force attacks against ESXi hosts can lead to complete compromise of virtualized environments, enabling attackers to deploy ransomware (like Hellcat or Black Basta), steal sensitive data, or disrupt critical services. This activity is particularly concerning in light of the increasing targeting of ESXi infrastructure by ransomware groups.

## Attack Chain

1. The attacker identifies an ESXi host as a potential target, possibly through network scanning or open-source intelligence.
2. The attacker initiates SSH connections to the ESXi host, attempting to authenticate with a list of common or stolen usernames and passwords.
3. The ESXi host logs each failed authentication attempt in its syslog. These logs contain the username, source IP address, and destination hostname.
4. The attacker continues to send SSH authentication requests, rapidly iterating through different username and password combinations.
5. If successful, the attacker gains an interactive shell on the ESXi host with privileged access.
6. The attacker disables security features, deploys ransomware payloads targeting virtual machines.
7. The attacker moves laterally within the ESXi environment, potentially compromising other virtual machines or hosts.
8. The attacker encrypts virtual machine files, rendering them inaccessible and demanding a ransom payment for decryption.

## Impact

A successful SSH brute-force attack on an ESXi host can lead to complete compromise of the virtualized environment. Observed impacts include the deployment of ransomware such as Hellcat and Black Basta, resulting in data encryption, system downtime, and significant financial losses. Organizations in various sectors, including healthcare, finance, and critical infrastructure, have been targeted. The number of affected virtual machines can range from a few to hundreds, depending on the size and configuration of the environment. Recovery efforts can be lengthy and costly, often requiring complete system rebuilds from backups.

## Recommendation

*   Configure ESXi hosts to forward syslog data to a centralized logging system (Splunk) to enable detection of brute-force attempts. Reference: "VMWare ESXi Syslog" in data_source.
*   Deploy the Sigma rule "ESXi SSH Brute Force Detection" to your SIEM to detect suspicious login patterns. Reference: Sigma rule below.
*   Investigate and block source IP addresses exhibiting high numbers of failed SSH login attempts against ESXi hosts. Reference: "src_ip" in the Sigma rule and IOCs.
*   Implement multi-factor authentication (MFA) for SSH access to ESXi hosts to mitigate the risk of successful brute-force attacks. This will reduce the effectiveness of credential-based attacks.
*   Enforce strong password policies and regularly audit user accounts with SSH access to ESXi hosts.
*   Apply rate limiting or connection limits to SSH services on ESXi hosts to slow down brute-force attempts.
