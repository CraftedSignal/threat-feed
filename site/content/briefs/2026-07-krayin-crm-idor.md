---
title: Krayin CRM Insecure Direct Object Reference Vulnerability (CVE-2026-61460)
slug: 2026-07-krayin-crm-idor
description: An Insecure Direct Object Reference (IDOR) vulnerability, CVE-2026-61460, in Krayin CRM through version 2.2.3 allows authenticated users to modify, update, or delete records owned by other users by exploiting missing record-level ownership validation in various controllers, leading to unauthorized data manipulation.
date: "2026-07-10T19:21:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - crm
  - web-application
  - vulnerability
vendors:
  - Krayin
products:
  - Krayin CRM
  - laravel-crm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: allows authenticated users
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1561
    technique_name: Disk Data Boobytrap
    evidence: modify, update, or delete records owned by other users
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: reassign ownership
    confidence_band: high
cves:
  - id: CVE-2026-61460
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61460
  - https://github.com/krayin/laravel-crm/issues/2559
  - https://github.com/krayin/laravel-crm/pull/2567
  - https://www.vulncheck.com/advisories/krayin-crm-insecure-direct-object-reference-via-controllers
---

Krayin CRM, specifically versions through 2.2.3, is affected by an Insecure Direct Object Reference (IDOR) vulnerability, tracked as CVE-2026-61460. This flaw resides within multiple controllers, including `LeadController`, `PersonController`, `OrganizationController`, `QuoteController`, and `ActivityController`. An authenticated user can exploit this vulnerability to bypass record-level ownership validation when performing edit, update, or destroy operations. This allows attackers to manipulate data belonging to other users, such as modifying or deleting their records, and even reassigning ownership of these records. The vulnerability stems from insufficient checks in the application's backend code that fail to confirm if the authenticated user is the legitimate owner of the record they are attempting to modify. This grants unauthorized data access and manipulation capabilities within the CRM system.

## Attack Chain

1. An attacker gains authenticated access to a Krayin CRM instance, possessing a valid user account.
2. The attacker identifies a target CRM record (e.g., a lead, person, organization, quote, or activity) that is owned by another user.
3. The attacker intercepts or crafts an HTTP request to one of the vulnerable controllers, such as `LeadController`, `PersonController`, `OrganizationController`, `QuoteController`, or `ActivityController`.
4. In the request, the attacker specifies the unique identifier (ID) of the target record owned by another user, rather than a record owned by their own account.
5. The attacker invokes an action like "edit," "update," or "destroy" on the specified record ID.
6. Due to the missing record-level ownership validation, the Krayin CRM application processes the request successfully.
7. The CRM system performs the requested operation, allowing the attacker to modify, update, or delete the record belonging to another user.
8. Optionally, the attacker can reassign the ownership of the manipulated record to another user or themselves, maintaining unauthorized control.

## Impact

Successful exploitation of CVE-2026-61460 can lead to severe data integrity and confidentiality issues within Krayin CRM deployments. Attackers can arbitrarily modify, delete, or exfiltrate sensitive customer and organizational data stored in the CRM, leading to potential data loss, corruption, or exposure. Furthermore, the ability to reassign record ownership can disrupt business processes, undermine data trust, and facilitate further unauthorized actions by obscuring the true ownership of critical information. Organizations using Krayin CRM through version 2.2.3 are at risk of significant operational disruption and compliance violations if this vulnerability remains unpatched.

## Recommendation

* Immediately apply patches or upgrade Krayin CRM to a version beyond 2.2.3 to remediate CVE-2026-61460, as described in the references.
* Implement robust input validation and authorization checks at the application layer to ensure that authenticated users can only interact with records they are authorized to access.
* Review web application firewall (WAF) configurations to identify and potentially block suspicious requests targeting `LeadController`, `PersonController`, `OrganizationController`, `QuoteController`, and `ActivityController` with unexpected record IDs or parameters.
* Monitor web server access logs for unusual patterns of access to CRM controller endpoints, especially those involving repeated attempts to modify or delete records belonging to different users.
