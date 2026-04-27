---
title: Synology SSL VPN Client Plaintext Password Storage Vulnerability (CVE-2021-47961)
slug: 2026-04-synology-vpn-vuln
description: Synology SSL VPN Client before 1.4.5-0684 stores passwords in plaintext, allowing remote attackers to potentially access or manipulate user PIN codes, leading to unauthorized VPN configuration and traffic interception.
date: "2026-04-10T10:16:03Z"
severities:
  - high
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

CVE-2021-47961 describes a vulnerability in Synology SSL VPN Client versions prior to 1.4.5-0684. The client software stores user passwords in plaintext, creating a security risk. An attacker with access to the system or the client's configuration files could potentially retrieve these passwords and use them to manipulate the VPN configuration. Successful exploitation of this vulnerability can lead to unauthorized access to the VPN, as well as the potential interception and monitoring of VPN…
