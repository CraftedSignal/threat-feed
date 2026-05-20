---
title: SonicWall Gen6 SSL-VPN MFA Bypass via CVE-2024-12802
slug: 2026-05-sonicwall-mfa-bypass
description: Threat actors exploited CVE-2024-12802, a vulnerability in SonicWall Gen6 SSL-VPN appliances, to bypass multi-factor authentication (MFA) after brute-forcing VPN credentials, leading to the deployment of ransomware-related tools.
date: "2026-05-20T21:19:58Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Initial Access Broker
tags:
  - vpn
  - mfa-bypass
  - cve-2024-12802
  - sonicwall
  - initial access
vendors:
  - SonicWall
products:
  - Gen6 SSL-VPN appliances
  - Gen7 devices
  - Gen8 devices
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2024-12802
    cvss: 9.1
    epss: 0.0006
references:
  - https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/
  - CVE-2024-12802
rules:
  - title: Detect SonicWall VPN CLI Login
    description: Detects VPN logins with sess=CLI indicating scripted or automated authentication attempts, potentially related to CVE-2024-12802 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - firewall
      - sonicwall
  - title: Detect SonicWall VPN Login Event ID 238 or 1080
    description: Detects SonicWall VPN login attempts indicated by Event ID 238 or 1080, which are associated with potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - firewall
      - sonicwall
rules_count: 2
---

In February and March 2026, ReliaQuest researchers responded to multiple intrusions exploiting CVE-2024-12802 on SonicWall Gen6 SSL-VPN appliances. The vulnerability allows attackers to bypass MFA by exploiting a missing enforcement for the UPN login format. Organizations that applied the firmware update without completing the manual LDAP reconfiguration remained vulnerable. The attacker's dwell time within the network ranged from 30 to 60 minutes, during which they conducted network reconnaissance and tested credential reuse before logging out, suggesting initial access brokering activity. This activity was seen "across multiple sectors and geographies". Gen7 and Gen8 devices are not vulnerable if updated to a newer firmware version. Gen6 devices reached end-of-life on April 16, 2026, and no longer receive security updates.

## Attack Chain

1.  Attacker brute-forces VPN credentials for SonicWall Gen6 SSL-VPN appliances.
2.  Attacker exploits CVE-2024-12802 due to incomplete patching (firmware update applied but LDAP configuration not updated).
3.  Attacker successfully authenticates to the VPN, bypassing MFA.
4.  Attacker conducts network reconnaissance to map out the internal network.
5.  Attacker tests credential reuse on internal systems.
6.  Attacker establishes a remote connection over RDP using a shared local administrator password to a domain-joined file server.
7.  Attacker attempts to deploy a Cobalt Strike beacon for command-and-control (C2).
8.  Attacker attempts to load a vulnerable driver, likely to disable endpoint protection using BYOVD techniques; EDR blocks the beacon and driver.

## Impact

The exploitation of CVE-2024-12802 allowed threat actors to gain unauthorized access to internal networks through SonicWall SSL-VPN appliances. In one instance, the attacker reached a domain-joined file server within 30 minutes of initial access. The compromised access can be sold to ransomware groups for further exploitation, leading to data theft, encryption, and financial losses. This vulnerability impacted organizations across multiple sectors and geographies, with rogue login attempts appearing as normal MFA flows in logs, masking the bypass.

## Recommendation

*   Apply the manual remediation steps for CVE-2024-12802 on SonicWall Gen6 devices: delete the existing LDAP configuration, remove locally cached LDAP users, remove the SSL VPN User Domain, reboot the firewall, recreate the LDAP configuration, and create a fresh backup (reference CVE-2024-12802).
*   Upgrade to actively supported SonicWall appliances (Gen7 or Gen8) to fully mitigate the risk from CVE-2024-12802 if possible, since Gen6 devices are EOL.
*   Monitor VPN logs for `sess="CLI"` activity, which indicates scripted or automated VPN authentication, a key indicator of CVE-2024-12802 exploitation.
*   Monitor VPN logs for event IDs 238 and 1080, which are strong signals of potential exploitation activity.
*   Implement detection rules to identify VPN logins from suspicious VPS/VPN infrastructure (see rules below).
