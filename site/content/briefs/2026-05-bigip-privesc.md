---
title: BIG-IP Privilege Escalation via Configuration Modification (CVE-2026-41953)
slug: 2026-05-bigip-privesc
description: CVE-2026-41953 describes a privilege escalation vulnerability in F5 BIG-IP systems where a highly privileged, authenticated attacker with the Resource Administrator role can modify configuration objects, leading to elevated privileges within the system.
date: "2026-05-13T16:24:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - f5
  - big-ip
vendors:
  - F5 Networks
products:
  - BIG-IP
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41953
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41953
  - https://my.f5.com/manage/s/article/K000160975
rules:
  - title: Detect Suspicious BIG-IP Configuration Changes
    description: Detects CVE-2026-41953 exploitation — Alerts on configuration changes made by Resource Administrators that could lead to privilege escalation in F5 BIG-IP systems.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - device_change
      - f5_big-ip
  - title: Detect BIG-IP Authentication Events from Unusual Locations
    description: Detects successful authentication events to BIG-IP systems originating from unusual or unexpected geographic locations.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - authentication
      - f5_big-ip
rules_count: 2
---

CVE-2026-41953 describes a vulnerability in F5 BIG-IP systems. An attacker with high privileges (Resource Administrator role or higher) and valid authentication can exploit this vulnerability to escalate their privileges. This is achieved by modifying configuration objects in a way that grants them higher access than initially intended. This vulnerability affects BIG-IP systems; software versions that have reached End of Technical Support (EoTS) are not evaluated. This vulnerability can be exploited by an insider threat or an attacker who has already compromised a highly privileged account. Successful exploitation allows the attacker to gain complete control over the BIG-IP system, potentially impacting network security and availability.

## Attack Chain

1. The attacker obtains valid credentials for a BIG-IP account with at least the Resource Administrator role.
2. The attacker authenticates to the BIG-IP management interface (GUI or CLI) using the compromised credentials.
3. The attacker identifies a configuration object that, when modified, can grant them elevated privileges. This could involve modifying user roles, access policies, or system settings.
4. The attacker uses the management interface or API to modify the identified configuration object.
5. The attacker's modifications are applied to the BIG-IP system configuration.
6. The attacker logs out and logs back in with the same account, or the system is restarted in order for the new privileges to be in effect.
7. The attacker now has elevated privileges, allowing them to perform actions beyond the scope of their original role.
8. The attacker leverages the elevated privileges to compromise other systems, exfiltrate data, or disrupt network operations.

## Impact

Successful exploitation of CVE-2026-41953 allows an attacker to escalate their privileges on a BIG-IP system. This can lead to complete control over the BIG-IP device, allowing them to reconfigure security policies, intercept network traffic, or disrupt services. The impact could include unauthorized access to sensitive data, network outages, and the compromise of other systems within the network.

## Recommendation

*   Apply available patches or hotfixes from F5 Networks to address CVE-2026-41953 as soon as possible.
*   Review and enforce the principle of least privilege for BIG-IP user accounts, limiting the number of users with the Resource Administrator role.
*   Monitor BIG-IP system logs for unauthorized configuration changes, particularly modifications to user roles and access policies. Deploy the Sigma rule `Detect Suspicious BIG-IP Configuration Changes` to identify potentially malicious configuration modifications.
*   Implement multi-factor authentication for all BIG-IP user accounts to reduce the risk of credential compromise.
