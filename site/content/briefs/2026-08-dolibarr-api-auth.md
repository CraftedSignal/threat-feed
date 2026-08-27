---
title: Dolibarr Members REST API Improper Authorization Vulnerability
slug: 2026-08-dolibarr-api-auth
description: An improper authorization vulnerability (CVE-2026-71504) in Dolibarr prior to version 24.0.0 allows authenticated users to overwrite the credentials of any account via the Members REST API.
date: "2026-08-24T20:06:34Z"
lastmod: "2026-08-27T21:10:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rest-api
  - privilege-escalation
  - cve-2026-71504
  - sqli
  - web-vulnerability
vendors:
  - Dolibarr
products:
  - Dolibarr (24.0.0)
  - Dolibarr
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An improper authorization vulnerability... that allows attackers... to reset the password of any user account.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Dolibarr before 24.0.0 contains a SQL injection in its CSV and XLSX import wizard.
    confidence_band: high
cves:
  - id: CVE-2026-71504
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71504
  - https://github.com/Dolibarr/dolibarr/releases/tag/24.0.0
  - https://www.vulncheck.com/advisories/dolibarr-members-rest-api-improper-authorization-via-password-reset
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81728
rules:
  - title: Detects CVE-2026-71504 Exploitation - Password Overwrite via Members API
    description: Detects potential exploitation of CVE-2026-71504 by identifying POST requests to the Members REST API that involve password fields or credentials updates.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect CVE-2026-81728 Exploitation - SQL Injection in Import Wizard
    description: Detects exploitation of the CSV/XLSX import wizard by monitoring for SQL keywords or injection syntax within the 'updatekeys' array parameter in web requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Dolibarr instances to 24.0.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-71504 vendor advisory.
  mitigation_plan:
    - priority: immediate
      action: Monitor/Restrict API access.
      owner: SOC
      addresses: CVE-2026-71504
      evidence: Source advisory recommendation.
updates:
  - at: "2026-08-27T21:10:34Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-81728 Exploitation - SQL Injection in Import Wizard'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-81728
---

Dolibarr versions prior to 24.0.0 are vulnerable to an improper authorization flaw (CVE-2026-71504) within the Members REST API. This vulnerability stems from a mass assignment issue that allows attackers possessing standard member-creation privileges to modify sensitive user account attributes. Specifically, an authenticated attacker can submit a crafted request to the API containing an arbitrary user identifier and a new password. The application fails to verify if the requester possesses the necessary permissions to change passwords, allowing the attacker to overwrite the credentials of any account, including the system administrator. This flaw facilitates full account takeover and enables the attacker to lock out legitimate users, presenting a significant risk to organizational identity management and data integrity.

## Attack Chain

1. Attacker obtains valid credentials for a standard user account with at least member-creation privileges in the Dolibarr instance.
2. Attacker performs reconnaissance to identify the endpoint for the Members REST API.
3. Attacker crafts a malicious HTTP POST request targeting the Members API endpoint.
4. Attacker inserts an arbitrary 'user_id' and the desired 'password' into the request body, leveraging mass assignment properties.
5. The Dolibarr server processes the request without enforcing authorization checks for password modification.
6. The backend updates the target user's credentials in the database to the attacker-supplied password.
7. Attacker logs into the target account (including administrative accounts) using the updated credentials.
8. Attacker gains full access to the victim's resources or performs administrative actions.

## Impact

Successful exploitation of CVE-2026-71504 results in unauthorized account takeover, including administrative accounts. This leads to complete compromise of the Dolibarr instance, potential exfiltration of sensitive member or organizational data, and denial of service for legitimate users who are locked out of their accounts. The vulnerability affects all Dolibarr installations running versions prior to 24.0.0.

## Recommendation

* Update all Dolibarr instances to version 24.0.0 or later immediately.
* Monitor web server logs for suspicious POST requests to the Members REST API, specifically looking for requests that include unexpected password change parameters.
* Audit logs for unauthorized password resets occurring through the API for administrative accounts.
* Restrict access to the Members REST API to only those service accounts or users strictly requiring member-creation privileges.
