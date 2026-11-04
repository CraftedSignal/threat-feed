---
brief_id: brief-2026-11-04-vtenext-sqli
event_id: brief-2026-11-04-vtenext-sqli
revision: 1
activity_at: "2026-11-04T22:07:01Z"
title: 'vtenext: SQL injection in Fax module (CVE-2025-71456)'
slug: 2026-11-vtenext-sqli
description: An SQL injection vulnerability in vtenext modules/Fax/EditView.php allows authenticated low-privileged users to extract sensitive database content, including password reset tokens.
date: "2026-11-04T22:07:01Z"
type: advisory
types:
  - advisory
severities:
  - high
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
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers can read arbitrary database contents, including password reset tokens stored in vte_userauthtoken, to take over other user accounts.
    confidence_band: high
cves:
  - id: CVE-2025-71456
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71456
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
---

vtenext versions prior to 25.02.2 contain an SQL injection vulnerability located in the `modules/Fax/EditView.php` component. An authenticated, low-privileged user can exploit this by providing a crafted `fieldname` parameter to the affected script. Successful exploitation allows for unauthorized read access to database tables, including the `vte_userauthtoken` table, which may lead to account takeover via token extraction.

## Impact

Successful exploitation results in unauthorized access to sensitive database information, specifically session or password reset tokens. This enables full account takeover of targeted users.

## Recommendation

- Upgrade to vtenext version 25.02.2 or later immediately to remediate the vulnerability.
- Audit database access logs for unusual queries originating from the `modules/Fax/EditView.php` endpoint.
- Restrict access to the `modules/Fax/EditView.php` file to authorized administrative roles only if an immediate upgrade is not feasible.
