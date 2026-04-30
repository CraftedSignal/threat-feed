---
title: Synology SSL VPN Client Plaintext Password Storage Vulnerability (CVE-2021-47961)
slug: 2026-04-synology-vpn-vuln
description: Synology SSL VPN Client before 1.4.5-0684 stores passwords in plaintext, allowing remote attackers to potentially access or manipulate user PIN codes, leading to unauthorized VPN configuration and traffic interception.
date: "2026-04-10T10:16:03Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - plaintext-password
  - vpn
  - synology
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2021-47961
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47961
  - https://www.synology.com/en-global/security/advisory/Synology_SA_26_05
rules:
  - title: Detect Synology VPN Client Configuration File Access
    description: Detects access to Synology SSL VPN client configuration files, which may contain plaintext passwords.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - file_event
      - windows
  - title: Detect Modification of Synology VPN Client Configuration File
    description: Detects modification to Synology SSL VPN client configuration files, which may indicate password compromise.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1547
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2021-47961 describes a vulnerability in Synology SSL VPN Client versions prior to 1.4.5-0684. The client software stores user passwords in plaintext, creating a security risk. An attacker with access to the system or the client's configuration files could potentially retrieve these passwords and use them to manipulate the VPN configuration. Successful exploitation of this vulnerability can lead to unauthorized access to the VPN, as well as the potential interception and monitoring of VPN traffic. This is particularly concerning for organizations relying on secure VPN connections for remote access and data transmission. This vulnerability was disclosed on April 10, 2026.

## Attack Chain

1.  Attacker gains unauthorized access to the targeted system, either through physical access or remote access methods.
2.  Attacker locates the Synology SSL VPN Client configuration file(s) on the compromised system.
3.  Attacker opens the configuration file and retrieves the plaintext password stored within.
4.  Attacker uses the retrieved password to access or modify the user's PIN code within the VPN client.
5.  Attacker reconfigures the VPN client settings, potentially redirecting traffic through a malicious server.
6.  User connects to the VPN using the modified configuration.
7.  All VPN traffic from the user's machine is now routed through the attacker's server.
8.  Attacker intercepts and monitors the user's VPN traffic, gaining access to sensitive data.

## Impact

Successful exploitation of CVE-2021-47961 allows attackers to gain unauthorized access to sensitive data transmitted through the VPN connection. The number of victims is dependent on the number of deployments using the vulnerable Synology SSL VPN client version prior to 1.4.5-0684. Sectors utilizing Synology SSL VPN clients for remote access are particularly at risk. A successful attack can lead to data breaches, intellectual property theft, and potential compromise of internal systems.

## Recommendation

*   Upgrade Synology SSL VPN Client to version 1.4.5-0684 or later to patch CVE-2021-47961.
*   Deploy the Sigma rule "Detect Synology VPN Client Configuration File Access" to detect unauthorized access to configuration files.
*   Monitor network traffic for unusual VPN connection patterns indicative of traffic redirection, using existing network monitoring tools.
