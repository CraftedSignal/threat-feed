---
brief_id: brief-2026-10-27-adobe-campaign-classic-sql-injection
event_id: brief-2026-10-27-adobe-campaign-classic-sql-injection
revision: 1
activity_at: "2026-10-27T20:23:13Z"
title: 'Adobe Campaign Classic: SQL Injection remote code execution (CVE-2026-105781)'
slug: 2026-10-adobe-campaign-classic-sql-injection
description: Adobe Campaign Classic is vulnerable to an unauthenticated SQL injection flaw (CVE-2026-105781) that allows for remote code execution, with public exploit code now available.
date: "2026-10-27T20:23:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:adobe:campaign_classic:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - rce
  - vulnerability
vendors:
  - Adobe
products:
  - Campaign Classic
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) vulnerability that could result in arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-105781
    cvss: 10
    kev_status: "false"
references:
  - https://www.adobe.com/trust/security/products/campaign/apsb26-162.html
  - https://sploitus.com/exploit?id=CVE-2026-105781
  - https://sploitus.com/exploit?id=CVE-2026-105781&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory Adobe Campaign Classic deployments and compare current versions against APSB26-162 release.
      owner: IT Operations
      due: 24h
      evidence: Adobe advisory APSB26-162
  hunt_leads:
    - lead: Monitor web server access logs for anomalous SQL injection syntax (e.g., OR 1=1, UNION SELECT, system-level function calls) directed at Campaign Classic API or web interface endpoints.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: SQL injection vulnerability identified in Adobe Campaign Classic.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches per APSB26-162.
      owner: IT Operations
      addresses: CVE-2026-105781
      evidence: Adobe security bulletin APSB26-162
---

Adobe Campaign Classic is affected by an SQL injection vulnerability (CVE-2026-105781) that permits an unauthenticated remote attacker to achieve arbitrary code execution in the context of the application user. This vulnerability carries a CVSS score of 10.0 and does not require user interaction. A proof-of-concept exploit is publicly available, increasing the risk of exploitation.

## Impact

The vulnerability allows an unauthenticated attacker to execute arbitrary SQL commands and achieve arbitrary code execution. This could lead to full system compromise, data exfiltration, or complete loss of availability for the Campaign Classic environment.

## Recommendation

1. Inventory all Adobe Campaign Classic instances within the environment.
2. Apply the vendor-provided security updates documented in APSB26-162 immediately.
3. Restrict network access to the Campaign Classic administrative and API interfaces to known, trusted management segments until patching is complete.
