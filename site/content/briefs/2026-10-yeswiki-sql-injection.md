---
brief_id: brief-2026-10-25-yeswiki-sql-injection
event_id: brief-2026-10-25-yeswiki-sql-injection
revision: 1
activity_at: "2026-10-25T14:31:50Z"
title: 'YesWiki: Unauthenticated SQL injection in SearchManager (CVE-2026-116207)'
slug: 2026-10-yeswiki-sql-injection
description: An unauthenticated SQL injection vulnerability in YesWiki versions 4.6.0-4.6.x and 5.0.0-alpha1-alpha3 allows remote attackers to perform subquery injection to extract database content or cause denial-of-service.
date: "2026-10-25T14:31:50Z"
lastmod: "2026-10-25T14:33:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Checked against NVD advisory details.
cpes:
  - cpe:2.3:a:yeswiki:yeswiki:*:*:*:*:*:*:*:*
  - cpe:2.3:a:yeswiki:yeswiki:4.6.2:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve-2026-116207
  - cve-2026-116211
vendors:
  - YesWiki
products:
  - YesWiki (4.6.0 <= version < 4.7.0)
  - YesWiki (5.0.0-alpha1 <= version < 5.0.0-alpha4)
  - YesWiki (4.6.2 <= version < 4.7.0)
  - YesWiki (4.5.0 <= version < 4.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: YesWiki 4.6.0 before 4.7.0 and 5.0.0-alpha1 before 5.0.0-alpha4 contains an unauthenticated SQL injection vulnerability in SearchManager::prepareSearchRequest().
    confidence_band: high
cves:
  - id: CVE-2026-116207
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-116208
    cvss: 8.1
    kev_status: "false"
  - id: CVE-2026-116211
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116207
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116208
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116211
rules:
  - title: Detects CVE-2026-116207 Exploitation - SQL injection in Bazar Search API
    description: Detects exploitation attempts against the Bazar entries search API where query parameters contain backtick characters used for alias injection.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-116211 Exploitation - SQL Injection in Bazar module
    description: Detects potential SQL injection attempts against the YesWiki Bazar module by monitoring POST requests for SQL syntax in the date_maj_fiche parameter.
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
    - action: Upgrade affected YesWiki instances to 4.7.0 or 5.0.0-alpha4.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-116207 advisory notes versions before 4.7.0 and 5.0.0-alpha4 are vulnerable.
    - action: Upgrade YesWiki to version 4.7.0 or later.
      owner: IT Operations
      due: 72h
      evidence: Vulnerability affects versions 4.6.2 before 4.7.0.
    - action: Upgrade YesWiki to 4.7.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-116211 fixed in 4.7.0
  hunt_leads:
    - lead: Identify unauthenticated requests to Bazar search endpoints containing backticks or SQL keywords like SLEEP, UNION, or SELECT.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows injection of subqueries such as SLEEP() via the Bazar entries search API.
    - lead: Identify unusual or unexpected synchronization events in ActivityPub logs originating from unknown or untrusted federated servers.
      technique_id: T1190
      data_needed:
        - YesWiki application logs
        - Federation activity audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can serve a poisoned outbox with cross-actor Delete, Update, or Create activities during admin-initiated sync.
    - lead: Hunt for anomalous SQL queries referencing wiki_users table in database logs
      technique_id: T1190
      data_needed:
        - Database audit logs
        - Web application logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthenticated attackers on default installs can inject a sub-SELECT against wiki_users
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block or sanitize backtick characters in search API parameters.
      owner: IT Operations
      addresses: CVE-2026-116207
      evidence: Vulnerability utilizes backtick-quoted aliases for injection.
    - priority: immediate
      action: Upgrade to YesWiki 4.7.0
      owner: IT Operations
      addresses: CVE-2026-116208
      evidence: Fixed in version 4.7.0.
updates:
  - at: "2026-10-25T14:33:04Z"
    level: L2
    summary: added coverage for YesWiki (4.6.2 <= version < 4.7.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116208
  - at: "2026-10-25T14:33:09Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-116211 Exploitation - SQL Injection in Bazar module'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116211
---

YesWiki contains an unauthenticated SQL injection vulnerability in the SearchManager::prepareSearchRequest() method. The flaw stems from improper sanitization of field names within the Bazar entries search API. Specifically, the query and searchfields parameters are placed into backtick-quoted aliases using only mysqli_real_escape_string, which is insufficient for backtick encapsulation. This allows attackers to break out of the alias context and execute arbitrary SQL subqueries.

## Impact
Successful exploitation allows unauthenticated attackers to read sensitive database records, including user password hashes, or perform denial-of-service attacks by injecting time-based commands such as SLEEP().

## Recommendation
- Upgrade YesWiki to version 4.7.0 or 5.0.0-alpha4 or later to remediate the vulnerability.
- Until patching is complete, restrict access to the public Bazar entries search API at the web application firewall or reverse proxy level.
- Review web server access logs for anomalous requests to the Bazar search endpoint containing backtick characters (`) or SQL keywords commonly used for subquery injection (e.g., SELECT, UNION, SLEEP).
