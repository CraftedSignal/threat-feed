---
title: Authentication Bypass in Team Password Manager via Password Reset Flow
slug: 2026-09-02-team-password-manager-auth-bypass
description: Team Password Manager versions prior to 14.184.308 contain a critical authentication bypass vulnerability in the local account password reset workflow that allows unauthenticated attackers to perform account takeovers.
date: "2026-09-02T03:10:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:teampasswordmanager:team_password_manager:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-application-security
  - credential-theft
vendors:
  - Team Password Manager
products:
  - Team Password Manager (< 14.184.308)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: Unauthenticated attackers can reset local account passwords and authenticate as those users to gain unauthorized access.
    confidence_band: high
cves:
  - id: CVE-2026-84699
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84699
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Team Password Manager to version 14.184.308 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-84699 remediation guidance.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Team Password Manager to 14.184.308 or later
      owner: IT Operations
      addresses: CVE-2026-84699
      evidence: NVD advisory
---

Team Password Manager versions prior to 14.184.308 are affected by a high-severity authentication bypass vulnerability, tracked as CVE-2026-84699. This flaw exists within the application's local account password reset mechanism, where the software fails to properly enforce authentication requirements. An unauthenticated remote attacker can exploit this weakness by submitting crafted requests to the password reset endpoint, effectively resetting the password for any local user account without knowing the current credentials. Successful exploitation results in complete account takeover, granting the attacker unauthorized access to sensitive stored credentials and administrative functions within the platform. Given the role of Team Password Manager in securing organization-wide secrets, this vulnerability presents a critical risk for credential exfiltration and lateral movement.

## Impact

Successful exploitation of CVE-2026-84699 allows an unauthenticated attacker to gain full control over local user accounts. In an enterprise environment, this leads to the compromise of the organization's master password repository, resulting in the exfiltration of all stored credentials, potential unauthorized access to downstream systems, and the total loss of confidentiality regarding the organization's secrets management.

## Recommendation

Prioritized actions for security and IT teams:
- Upgrade Team Password Manager to version 14.184.308 or later immediately to address CVE-2026-84699.
- Review web server access logs for anomalous POST requests targeting the local account password reset endpoint.
- Audit all local user accounts for unexpected password changes or unusual login activity originating from unrecognized IP addresses.
