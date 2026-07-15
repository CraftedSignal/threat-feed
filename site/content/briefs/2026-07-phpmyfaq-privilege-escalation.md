---
title: phpMyFAQ Privilege Escalation via User Add API Endpoint (CVE-2026-57996)
slug: 2026-07-phpmyfaq-privilege-escalation
description: A privilege escalation vulnerability (CVE-2026-57996) exists in phpMyFAQ before version 4.1.5, allowing a delegated administrator with specific permissions to create a SuperAdmin account through the `/admin/api/user/add` API endpoint, leading to full instance takeover.
date: "2026-07-15T12:24:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - phpmyfaq
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'A delegated administrator with USER_ADD/EDIT/DELETE permissions can call POST /admin/api/user/add with isSuperAdmin: true and attacker-chosen credentials to create a SuperAdmin account, then authenticate as that account to achieve full instance takeover.'
    confidence_band: high
cves:
  - id: CVE-2026-57996
    cvss: 8.8
references:
  - https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-r2f4-v277-hvw9
  - https://www.vulncheck.com/advisories/phpmyfaq-privilege-escalation-via-missing-superadmin-guard-in-user-add-endpoint
---

A critical privilege escalation vulnerability, identified as CVE-2026-57996, has been discovered in phpMyFAQ versions prior to 4.1.5. This flaw impacts the `user/add` API endpoint, enabling an attacker with existing delegated administrator permissions (specifically `USER_ADD/EDIT/DELETE` permissions) to illicitly create a SuperAdmin account. By crafting a specific HTTP POST request to `/admin/api/user/add` that includes the `isSuperAdmin: true` parameter along with chosen credentials, the attacker can bypass intended access controls. Successful exploitation grants the attacker full administrative control over the phpMyFAQ instance, allowing for unauthorized data access, modification, or further compromise of the underlying system. This vulnerability highlights a critical lack of proper privilege management in the application's API, making it susceptible to malicious insiders or compromised lower-privilege accounts.

## Attack Chain

1. An attacker obtains or already possesses delegated administrator credentials within a phpMyFAQ instance, requiring `USER_ADD/EDIT/DELETE` permissions.
2. The attacker crafts a malicious HTTP POST request targeting the vulnerable `/admin/api/user/add` endpoint of the phpMyFAQ application.
3. The crafted POST request body includes the parameter `isSuperAdmin: true`, attempting to designate the new user as a SuperAdmin.
4. The attacker also specifies desired credentials (username and password) for the new SuperAdmin account within the same request.
5. The phpMyFAQ application, due to improper privilege management (CWE-269), processes the request and creates a new user account with SuperAdmin privileges.
6. The attacker then uses the newly created SuperAdmin credentials to authenticate to the phpMyFAQ application.
7. Upon successful authentication, the attacker gains full administrative control over the entire phpMyFAQ instance, achieving complete system takeover.

## Impact

Successful exploitation of CVE-2026-57996 grants an attacker full administrative control over the affected phpMyFAQ instance. This allows for complete instance takeover, leading to unauthorized access, modification, or deletion of all data stored within the FAQ system, including sensitive configuration, user information, and content. The compromised SuperAdmin privileges could also be leveraged to execute arbitrary code on the underlying server, depending on the environment, potentially leading to further network intrusion, data exfiltration, or establishment of persistent access within the organization's infrastructure. While no specific victim counts are provided, any organization utilizing vulnerable versions of phpMyFAQ is at risk of such a high-impact compromise.

## Recommendation

* Patch CVE-2026-57996 by upgrading all phpMyFAQ installations to version 4.1.5 or later immediately.
* Review web server access logs for `POST` requests to `/admin/api/user/add` for unusual activity, specifically checking for the creation of new administrator accounts not initiated through standard administrative interfaces.
