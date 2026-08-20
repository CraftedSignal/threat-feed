---
title: Privilege Escalation in FreeIPA via Kerberos Principal Name Collision
slug: 2026-08-freeipa-privilege-escalation
description: CVE-2026-13097 is a privilege escalation vulnerability in FreeIPA where the 389-ds directory server fails to enforce uniqueness constraints on Kerberos principal names, allowing attackers with LDAP write access to impersonate privileged service principals.
date: "2026-08-20T13:14:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - identity-management
  - kerberos
vendors:
  - FreeIPA
products:
  - FreeIPA
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A privilege escalation flaw was found in FreeIPA allowing a user with sufficient LDAP write privileges to create a service principal that impersonates an existing privileged one.
    confidence_band: high
cves:
  - id: CVE-2026-13097
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13097
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - IAM Team
  immediate_actions:
    - action: Patch FreeIPA installations to resolve CVE-2026-13097
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-13097 advisory
  mitigation_plan:
    - priority: immediate
      action: Audit LDAP write permissions and identify non-essential accounts with such access
      owner: IAM Team
      addresses: CVE-2026-13097
      evidence: Vulnerability requires LDAP write privileges to exploit
---

A high-severity privilege escalation vulnerability (CVE-2026-13097) exists in FreeIPA due to an improper uniqueness constraint check for Kerberos principal name attributes within the 389-ds directory server. The flaw stems from the server's failure to recognize equivalent representations of the same principal name. An attacker possessing LDAP write privileges can create a service principal that shadows or impersonates an existing, highly privileged service principal. By successfully creating this collision, the attacker can intercept or gain unauthorized access to Kerberos service tickets intended for sensitive services within the environment. This escalation path presents a significant risk to the integrity of the Identity and Access Management (IAM) infrastructure, potentially enabling full domain compromise by an authenticated user with restricted LDAP permissions. Organizations utilizing FreeIPA as their central authentication and identity management solution should prioritize auditing LDAP access control lists and reviewing service principal registrations for irregularities.

## Impact

Successful exploitation of CVE-2026-13097 allows an authenticated user to perform service impersonation, leading to unauthorized access to sensitive Kerberos-authenticated services. Given the reliance on Kerberos for authentication in enterprise FreeIPA deployments, this vulnerability can lead to full domain compromise, resulting in complete unauthorized access to corporate resources, data exfiltration, or the ability to modify domain-wide security policies.

## Recommendation

* Apply the security patches provided by the FreeIPA project or your Linux distribution maintainer to address CVE-2026-13097 immediately.
* Audit all accounts with LDAP write permissions within your FreeIPA environment to identify and restrict unauthorized access.
* Monitor the FreeIPA 389-ds directory server logs for abnormal service principal creation events, specifically focusing on duplicate or near-identical principal names.
* Audit currently registered service principals for any anomalies in naming conventions or ownership that may indicate previous exploitation.
