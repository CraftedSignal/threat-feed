---
title: RUGGEDCOM CROSSBOW SAM-P Privilege Escalation Vulnerability (CVE-2026-27668)
slug: 2026-04-ruggdcom-privilege-escalation
description: CVE-2026-27668 allows authenticated User Administrators in RUGGEDCOM CROSSBOW Secure Access Manager Primary (SAM-P) to escalate their privileges and access any device group, due to an incorrect privilege assignment in versions prior to V5.8.
date: "2026-04-14T09:18:18Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - ruggedcom
  - privilege-escalation
  - cve-2026-27668
  - sam-p
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27668
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27668
  - https://cert-portal.siemens.com/productcert/html/ssa-741509.html
rules:
  - title: Detect RUGGEDCOM SAM-P Group Membership Modification
    description: Detects modifications to user group memberships within RUGGEDCOM SAM-P, which could indicate privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect RUGGEDCOM SAM-P Admin Login Activity
    description: Detects successful login events to the RUGGEDCOM SAM-P admin interface, which can be used to monitor for suspicious admin activity
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-27668, affects RUGGEDCOM CROSSBOW Secure Access Manager Primary (SAM-P) versions prior to V5.8. The vulnerability stems from User Administrators being granted the ability to administer groups they belong to. An attacker with User Administrator privileges can exploit this flaw to escalate their own privileges, granting themselves unauthorized access to any device group at any access level. This vulnerability poses a significant risk to organizations relying on RUGGEDCOM CROSSBOW SAM-P for secure access management, as it could lead to unauthorized access to sensitive devices and data. Successful exploitation allows an attacker to bypass intended access controls.

## Attack Chain

1. An attacker gains valid User Administrator credentials to the RUGGEDCOM CROSSBOW SAM-P. This could be through legitimate access or by compromising an existing account.
2. The attacker logs into the RUGGEDCOM CROSSBOW SAM-P web interface using their compromised or legitimate User Administrator credentials.
3. The attacker navigates to the group management section of the SAM-P interface.
4. The attacker modifies the group membership to include their own user account into a higher privileged group, or one with access to restricted devices.
5. The attacker assigns themselves permissions within the targeted device group, granting themselves full administrative or read/write access.
6. The attacker logs out and then logs back in to SAM-P to refresh their permissions and apply the changes.
7. The attacker uses their newly acquired privileges to access and manage devices and data within the targeted device group.
8. The attacker performs unauthorized actions on the devices or exfiltrates sensitive data.

## Impact

Successful exploitation of CVE-2026-27668 allows a malicious User Administrator to escalate their privileges within RUGGEDCOM CROSSBOW SAM-P. This could lead to complete control over managed devices, data breaches, and disruption of critical infrastructure. The impact of this vulnerability is significant, especially for organizations in critical infrastructure sectors that rely on RUGGEDCOM products. An attacker could gain unauthorized access to industrial control systems (ICS) or supervisory control and data acquisition (SCADA) systems.

## Recommendation

*   Upgrade RUGGEDCOM CROSSBOW Secure Access Manager Primary (SAM-P) to version V5.8 or later to patch CVE-2026-27668.
*   Monitor user activity within RUGGEDCOM CROSSBOW SAM-P for suspicious privilege escalations, referencing the attack chain described above.
*   Implement strict access controls and regularly review user permissions to minimize the attack surface.
*   Deploy the Sigma rule "Detect RUGGEDCOM SAM-P Group Membership Modification" to identify unauthorized changes to user group memberships.
