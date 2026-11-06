---
brief_id: brief-2026-11-06-craft-cms-sqli-9b34e80d
event_id: brief-2026-11-06-craft-cms-sqli-9b34e80d
revision: 1
activity_at: "2026-11-06T17:24:00Z"
title: 'Craft CMS: SQL injection in GraphQL eager-loading (CVE-2026-123491)'
slug: 2026-11-craft-cms-sqli-9b34e80d
description: Craft CMS versions 4.x before 4.18.9 and 5.x before 5.11.2 are vulnerable to SQL injection via the GraphQL eager-loading mechanism, allowing unauthenticated attackers to disclose arbitrary database content.
date: "2026-11-06T17:24:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of GraphQL API monitoring
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
vendors:
  - Craft CMS
products:
  - Craft CMS (4.0.0-4.18.9, 5.0.0-5.11.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can supply a parenthesized select argument to inject SQL expressions and read arbitrary database content.
    confidence_band: high
cves:
  - id: CVE-2026-123491
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123491
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Craft CMS to 4.18.9 or 5.11.2
      owner: IT Operations
      due: 24h
      evidence: Source advises update to these versions to patch vulnerability
  hunt_leads:
    - lead: Identify anomalous GraphQL POST requests containing SQL syntax in select arguments
      technique_id: T1190
      data_needed:
        - Web server access logs
        - GraphQL application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers supply a parenthesized select argument to inject SQL expressions
  mitigation_plan:
    - priority: immediate
      action: Apply security patch to affected Craft CMS versions
      owner: IT Operations
      addresses: CVE-2026-123491
      evidence: NVD advisory for CVE-2026-123491
---

Craft CMS contains an SQL injection vulnerability in the GraphQL eager-loading component. Unauthenticated attackers can supply a crafted select argument within eager-loadable nodes, which are then improperly processed by the EagerLoadPlan criteria. This flaw allows unauthorized read access to database records, including password hashes and session tokens.

## Impact
Successful exploitation allows unauthenticated remote attackers to bypass application-level access controls and extract sensitive database contents. The vulnerability affects the confidentiality of the entire database, including authentication credentials and active session identifiers.

## Recommendation
- Update Craft CMS installations to version 4.18.9 or 5.11.2 immediately to address the insecure handling of GraphQL arguments.
- Review database access logs for unusual queries originating from GraphQL API endpoints.
- Reset application-level credentials and invalidate active session tokens if indicators of database enumeration are identified.
