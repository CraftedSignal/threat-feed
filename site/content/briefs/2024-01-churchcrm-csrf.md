---
title: ChurchCRM < 7.2.0 Family Record Deletion CSRF Vulnerability
slug: 2024-01-churchcrm-csrf
description: ChurchCRM versions prior to 7.2.0 are vulnerable to a CSRF attack on the family record deletion endpoint allowing an attacker to trigger deletion of family records by enticing an authenticated administrator to visit a malicious page.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - CVE-2026-40581
  - csrf
  - churchcrm
  - data-deletion
vendors:
  - ChurchCRM
products:
  - ChurchCRM
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-40581
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40581
rules:
  - title: Detect ChurchCRM Family Record Deletion Request
    description: Detects requests to the SelectDelete.php endpoint in ChurchCRM which is vulnerable to CSRF.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect ChurchCRM SelectDelete.php Direct Access
    description: Detects direct access to the SelectDelete.php endpoint in ChurchCRM which is used to delete family records and is vulnerable to CSRF.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ChurchCRM, an open-source church management system, is susceptible to a critical Cross-Site Request Forgery (CSRF) vulnerability in versions prior to 7.2.0. Specifically, the family record deletion endpoint (SelectDelete.php) lacks CSRF token validation. This allows an attacker to craft a malicious web page that, when visited by an authenticated ChurchCRM administrator, will silently trigger the deletion of family records. The scope of this vulnerability extends to all associated data, including notes, pledges, persons, and property information. Successful exploitation results in irreversible data loss without user confirmation. Users are advised to upgrade to version 7.2.0 or later to mitigate this risk.

## Attack Chain

1.  Attacker identifies a vulnerable ChurchCRM instance running a version prior to 7.2.0.
2.  Attacker crafts a malicious HTML page containing an `<img>` or `<iframe>` tag that makes a GET request to `SelectDelete.php` with the ID of the target family record.  The URL looks like: `https://example.com/ChurchCRM/FamilyView.php?FamilyID=123&Action=Delete`.
3.  Attacker social engineers an authenticated ChurchCRM administrator into visiting the malicious HTML page (e.g., via phishing or embedding the page on a compromised website).
4.  The administrator's browser automatically sends the GET request to `SelectDelete.php` along with the administrator's valid session cookies.
5.  The ChurchCRM server, lacking CSRF protection, processes the request and deletes the specified family record and all associated data.
6.  The targeted family record, along with associated notes, pledges, persons, and property data, is permanently and irreversibly deleted from the ChurchCRM database.
7.  The attacker achieves the objective of data deletion and potential disruption of church management operations.

## Impact

A successful CSRF attack against ChurchCRM can result in the permanent and irreversible deletion of sensitive family records and associated data, potentially affecting hundreds or thousands of individuals depending on the size of the church and its record-keeping practices. This data loss can disrupt church operations, damage relationships with members, and lead to legal or regulatory compliance issues depending on the nature of the stored data. The lack of user interaction required for this exploit makes it particularly dangerous as administrators may be unaware that data is being deleted.

## Recommendation

*   Upgrade ChurchCRM to version 7.2.0 or later to patch the CSRF vulnerability in `SelectDelete.php` (see Overview).
*   Deploy the provided Sigma rule to detect suspicious requests to `SelectDelete.php` (see Rules).
*   Implement web application firewall (WAF) rules to block requests to `SelectDelete.php` that lack a valid CSRF token, if possible.
*   Educate ChurchCRM administrators about the risks of CSRF attacks and the importance of avoiding suspicious links or websites.
