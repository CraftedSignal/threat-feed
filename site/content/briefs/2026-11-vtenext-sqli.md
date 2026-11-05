---
brief_id: brief-2026-11-04-vtenext-sqli
event_id: brief-2026-11-04-vtenext-sqli
revision: 2
activity_at: "2026-11-05T00:08:59Z"
revision_history:
  - revision: 2
    at: "2026-11-05T00:08:59Z"
    checksum: sha256:7cb451148aa606b402b505a28ad3abf13cb6195c9f99b2060c1b6d1b913f6198
    summary: severity → critical; added CVE-2025-71457
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - rules
      - severity
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2025-71457
title: 'vtenext: SQL injection in Fax module (CVE-2025-71456)'
slug: 2026-11-vtenext-sqli
description: An SQL injection vulnerability in vtenext modules/Fax/EditView.php allows authenticated low-privileged users to extract sensitive database content, including password reset tokens.
date: "2026-11-04T22:07:01Z"
lastmod: "2026-11-05T00:05:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Manual verification of application logic requested.
cpes:
  - cpe:2.3:a:vtenext:vtenext:*:*:*:*:*:*:*:*
vendors:
  - vtenext
products:
  - vtenext (< 25.02.2)
  - vtenext (< 25.02.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers can read arbitrary database contents, including password reset tokens stored in vte_userauthtoken, to take over other user accounts.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers knowing a valid user_name can send action=change_password to RecoverPwd::displayChangePwd() and log in as administrators.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An unauthenticated attacker can change any account password via hub/rpwd.php without token verification.
    confidence_band: high
cves:
  - id: CVE-2025-71456
    cvss: 8.1
    kev_status: "false"
  - id: CVE-2025-71457
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71456
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71457
rules:
  - title: Detects CVE-2025-71457 Exploitation - Password Change Bypass
    description: Detects unauthenticated password change attempts targeting hub/rpwd.php
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - persistence
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade vtenext to version 25.02.2 or later.
      owner: IT Operations
      due: 24h
      evidence: vtenext before 25.02.2 contains an SQL injection vulnerability.
    - action: Patch vtenext to version 25.02.1 or later
      owner: IT Operations
      due: 24h
      evidence: vtenext 25.02 before 25.02.1 contains an authentication bypass
  hunt_leads:
    - lead: Hunt for HTTP GET/POST requests to modules/Fax/EditView.php containing SQL injection patterns in the fieldname parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-uri-query, cs-method)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Authenticated low-privileged users to inject SQL by supplying a crafted fieldname parameter to modules/Fax/EditView.php.
  mitigation_plan:
    - priority: immediate
      action: Apply security patch by upgrading to vtenext 25.02.2.
      owner: IT Operations
      addresses: CVE-2025-71456
      evidence: vtenext before 25.02.2 contains an SQL injection vulnerability.
    - priority: immediate
      action: Upgrade vtenext to 25.02.1
      owner: IT Operations
      addresses: CVE-2025-71457
      evidence: vtenext 25.02 before 25.02.1 contains an authentication bypass
updates:
  - at: "2026-11-05T00:05:37Z"
    level: L3
    summary: severity → critical; added CVE-2025-71457
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2025-71457
---

vtenext versions prior to 25.02.2 contain an SQL injection vulnerability located in the `modules/Fax/EditView.php` component. An authenticated, low-privileged user can exploit this by providing a crafted `fieldname` parameter to the affected script. Successful exploitation allows for unauthorized read access to database tables, including the `vte_userauthtoken` table, which may lead to account takeover via token extraction.

## Impact

Successful exploitation results in unauthorized access to sensitive database information, specifically session or password reset tokens. This enables full account takeover of targeted users.

## Recommendation

- Upgrade to vtenext version 25.02.2 or later immediately to remediate the vulnerability.
- Audit database access logs for unusual queries originating from the `modules/Fax/EditView.php` endpoint.
- Restrict access to the `modules/Fax/EditView.php` file to authorized administrative roles only if an immediate upgrade is not feasible.
