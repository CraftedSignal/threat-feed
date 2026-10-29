---
brief_id: brief-2026-10-26-crocoblock-jetengine-sql-injection
event_id: brief-2026-10-26-crocoblock-jetengine-sql-injection
revision: 2
activity_at: "2026-10-29T21:25:44Z"
revision_history:
  - revision: 2
    at: "2026-10-29T21:25:44Z"
    checksum: sha256:97f9016d673e9457f78ad71dc23717b306c6de6ef9f86610c47db537f02dd0bf
    summary: added coverage for JetEngine (<= 3.9.0.1)
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - qa_status
      - references
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-39736
title: 'Crocoblock JetEngine: SQL injection (CVE-2026-115608)'
slug: 2026-10-crocoblock-jetengine-sql-injection
description: The Crocoblock JetEngine plugin is affected by an Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) vulnerability in versions up to 3.9.0.
date: "2026-10-26T11:41:55Z"
lastmod: "2026-10-29T21:24:30Z"
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
  validation_status: Source verified against NVD data.
cpes:
  - cpe:2.3:a:crocoblock:jetengine:*:*:*:*:*:*:*:*
  - cpe:2.3:a:crocoblock:jetengine:*:*:*:*:*:wordpress:*:*
vendors:
  - Crocoblock
products:
  - JetEngine (n/a through 3.9.0)
  - JetEngine (<= 3.9.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) vulnerability in Crocoblock JetEngine jet-engine allows SQL Injection.
    confidence_band: high
cves:
  - id: CVE-2026-115608
    cvss: 8.5
    kev_status: "false"
  - id: CVE-2026-39736
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115608
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39736
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch JetEngine to version 3.9.0.2 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-39736 affects versions up to 3.9.0.1
  hunt_leads:
    - lead: Inspect web server logs for SQL injection patterns in parameters related to JetEngine
      technique_id: T1190
      data_needed:
        - web_access_logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is an SQL injection flaw in a WordPress plugin
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to detect SQL injection payloads
      owner: SOC
      addresses: CVE-2026-39736
      evidence: SQL injection vulnerability necessitates application-layer filtering
updates:
  - at: "2026-10-29T21:24:30Z"
    level: L2
    summary: added coverage for JetEngine (<= 3.9.0.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-39736
---

Crocoblock JetEngine plugin is affected by an SQL Injection vulnerability, identified as CVE-2026-115608. This issue arises from improper neutralization of special elements used in an SQL command and affects versions up to 3.9.0.
