---
title: NoSQL Injection Vulnerability in Budibase MongoDB Integration
slug: 2026-08-budibase-nosql-injection
description: Budibase versions prior to 3.40.0 are vulnerable to NoSQL injection in the MongoDB datasource due to improper handling of user-supplied parameters, allowing unauthorized data access and potential server-side execution.
date: "2026-08-13T12:56:46Z"
lastmod: "2026-08-18T08:50:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - web-vulnerability
  - budibase
  - web-application
  - privilege-escalation
  - auth-bypass
  - web-application-vulnerability
  - authorization-bypass
  - cloud-security
vendors:
  - Budibase
products:
  - Budibase
  - Budibase (before 3.40.0)
  - Budibase (3.39.4 to 3.39.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'Budibase before 3.40.0 contains a NoSQL injection vulnerability in the MongoDB datasource integration where user-supplied parameters are enriched with handlebars using noEscaping: true and parsed without operator filtering.'
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: any authenticated user — including a lowest-privilege BASIC app user — can reassign the tenant account-holder (top-privilege admin) email to an attacker-controlled address.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers with table read permissions can retrieve datasource configurations through the read API to obtain live backend database credentials and service account keys.
    confidence_band: high
cves:
  - id: CVE-2026-73617
    cvss: 7.1
    epss: 0.00202
  - id: CVE-2026-72855
    cvss: 8.5
    epss: 0.00273
  - id: CVE-2026-72856
    cvss: 8.1
    epss: 0.00327
  - id: CVE-2026-72857
    cvss: 7.7
    epss: 0.00258
  - id: CVE-2026-72859
    cvss: 7.7
    epss: 0.00181
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73617
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72855
  - https://github.com/Budibase/budibase/security/advisories/GHSA-xg5g-26x8-cvf4
  - https://www.vulncheck.com/advisories/budibase-before-dns-rebinding-ssrf-via-openapi-and-rest
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72856
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72857
  - https://github.com/Budibase/budibase/security/advisories/GHSA-6mpp-gfg5-x2vv
  - https://www.vulncheck.com/advisories/budibase-before-credential-exposure-via-string-fields
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2849
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72859
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2000
rules:
  - title: Detect Potential Exploitation of CVE-2026-72859
    description: Detects unauthorized attempts to access the S3 attachment upload endpoint by users with low privileges, as characterized by POST requests to the attachment route.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Budibase to version 3.40.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-73617 vendor patch release
  mitigation_plan:
    - priority: immediate
      action: Review MongoDB service account permissions used by Budibase
      owner: IT Operations
      addresses: CVE-2026-73617
      evidence: NoSQL injection allows modification or deletion of collection data
updates:
  - at: "2026-08-14T00:06:48Z"
    level: L2
    summary: added coverage for Budibase
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72856
  - at: "2026-08-14T00:06:56Z"
    level: L2
    summary: added coverage for budibase
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72857
  - at: "2026-08-14T14:06:15Z"
    level: L2
    summary: added CVE-2026-72855 +2
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2849
  - at: "2026-08-14T14:12:57Z"
    level: L2
    summary: 'added detection rule: Detect Potential Exploitation of CVE-2026-72859'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72859
  - at: "2026-08-18T08:50:03Z"
    level: L2
    summary: added CVE-2026-72859
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2000
---

Budibase versions prior to 3.40.0 contain a critical NoSQL injection vulnerability within the MongoDB datasource integration. The vulnerability stems from the application's processing of user-supplied parameters using Handlebars with the 'noEscaping: true' setting enabled, combined with a lack of robust operator filtering. 

This flaw allows an attacker to inject MongoDB-specific operators directly into query parameters. Because the input is not sanitized or restricted, an attacker can manipulate database queries to bypass existing row-level or per-user access controls. The impact is severe, enabling unauthorized read access to arbitrary documents, potential modification or deletion of collection data, and the execution of server-side JavaScript through operators such as '$where'. This vulnerability is particularly dangerous in environments where the Budibase backend connects to MongoDB databases containing sensitive business logic or user data.

## Impact

Successful exploitation allows attackers to bypass application-level access controls, leading to unauthorized data exfiltration or modification. In instances where the MongoDB instance allows the '$where' operator, attackers could escalate the impact to arbitrary code execution on the database server. This impacts all organizations using Budibase 3.39.x and earlier versions that integrate with MongoDB.

## Recommendation

* Upgrade Budibase instances to version 3.40.0 or later immediately to patch CVE-2026-73617.
* Audit logs for suspicious MongoDB queries involving unconventional operators (e.g., $where, $gt, $ne, $regex) originating from the Budibase application server.
* Implement strict input validation and query parameterization for any user-facing inputs bound to MongoDB datasource queries.
* Apply the principle of least privilege to the service account credentials used by Budibase to connect to MongoDB, restricting permissions to only those necessary for required operations.
