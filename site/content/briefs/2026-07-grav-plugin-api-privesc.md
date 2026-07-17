---
title: Grav Plugin API Privilege Escalation via Authorization Bypass (CVE-2026-62233)
slug: 2026-07-grav-plugin-api-privesc
description: A privilege escalation vulnerability (CVE-2026-62233) in grav-plugin-api before version 1.0.6 allows non-super api.users.write managers to bypass authorization checks on administrative API endpoints, enabling the creation of super-admin API keys or disabling super-admin Two-Factor Authentication (2FA), leading to full Grav instance takeover.
date: "2026-07-17T02:37:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - grav
vendors:
  - getgrav
products:
  - grav-plugin-api
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: grav-plugin-api before 1.0.6 fails to validate super-admin status in createApiKey, generate2fa, and disable2fa endpoints, allowing non-super api.users.write managers to escalate to super-admin.
    confidence_band: high
cves:
  - id: CVE-2026-62233
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62233
  - https://github.com/getgrav/grav/security/advisories/GHSA-8gg4-rvvv-cq96
  - https://www.vulncheck.com/advisories/grav-plugin-api-privilege-escalation-via-createapikey
---

CVE-2026-62233 identifies a critical authorization bypass vulnerability within the `grav-plugin-api` for Grav CMS, affecting all versions prior to 1.0.6. This flaw stems from an insufficient validation of user privileges when processing requests to the `createApiKey`, `generate2fa`, and `disable2fa` API endpoints. An attacker who has already obtained initial access as a low-privileged `api.users.write` manager can exploit this vulnerability to escalate their privileges to super-admin level. By abusing these endpoints, the attacker can either mint new API keys with super-admin permissions or disable the Two-Factor Authentication (2FA) for existing super-admin accounts, effectively granting them full administrative control over the Grav instance. This vulnerability poses a significant risk as it can lead to complete compromise of the affected system.

## Attack Chain

1. An attacker gains initial access to the Grav instance with a low-privileged account, specifically one granted the `api.users.write` manager role.
2. The attacker identifies and targets the `createApiKey`, `generate2fa`, or `disable2fa` API endpoints exposed by the `grav-plugin-api`.
3. The attacker crafts an API request to one of these endpoints, typically specifying a super-admin user account or parameters that would affect super-admin privileges.
4. Due to the vulnerability (CVE-2026-62233), the `grav-plugin-api` version prior to 1.0.6 fails to properly validate whether the initiating user has super-admin status.
5. If the attacker uses the `createApiKey` endpoint, a new API key is successfully generated and bound to a super-admin account, granting the attacker super-admin capabilities.
6. Alternatively, if the attacker uses the `disable2fa` endpoint, the Two-Factor Authentication for a target super-admin account is successfully removed.
7. The attacker then utilizes the newly acquired super-admin API key or leverages the disabled 2FA on a super-admin account to log in and gain full administrative control over the Grav instance.
8. With super-admin privileges, the attacker achieves full instance takeover, allowing for arbitrary code execution, data manipulation, exfiltration, or further lateral movement.

## Impact

The successful exploitation of CVE-2026-62233 leads to complete administrative control over the affected Grav CMS instance. Attackers can gain unrestricted access to all data, settings, and functionalities, including the ability to modify website content, access sensitive user information, install malicious plugins, or deploy web shells. This privilege escalation undermines all security controls, such as 2FA, for super-admin accounts. The consequence is a full compromise of the web application, potentially leading to data breaches, website defacement, or use of the compromised server for further attacks.

## Recommendation

* Patch CVE-2026-62233 immediately by updating `grav-plugin-api` to version 1.0.6 or later on all affected Grav CMS instances.
* Review all `api.users.write` managers for suspicious API key creation or 2FA modifications following the exploitation window described in CVE-2026-62233.
* Implement strong access controls and principle of least privilege for all user accounts accessing API endpoints to mitigate risks from vulnerabilities like CVE-2026-62233.
