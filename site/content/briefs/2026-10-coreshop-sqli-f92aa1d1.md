---
brief_id: brief-2026-10-30-coreshop-sqli-f92aa1d1
event_id: brief-2026-10-30-coreshop-sqli-f92aa1d1
revision: 1
activity_at: "2026-10-30T15:31:38Z"
title: 'CoreShop: Unauthenticated SQL injection in GetGoodsPageList (CVE-2026-119656)'
slug: 2026-10-coreshop-sqli-f92aa1d1
description: CoreShop versions up to 1.5.5 contain an unauthenticated SQL injection vulnerability in the api/Agent/GetGoodsPageList endpoint, allowing attackers to extract sensitive data via blind SQL injection techniques.
date: "2026-10-30T15:31:38Z"
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
cpes:
  - cpe:2.3:a:coreunion:coreshop:*:*:*:*:*:*:*:*
vendors:
  - CoreUnion
products:
  - CoreShop (<= 1.5.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CoreShop through 1.5.5 contains an unauthenticated sql injection vulnerability in the api/Agent/GetGoodsPageList endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-119656
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119656
rules:
  - title: Detects CVE-2026-119656 Exploitation - Blind SQL Injection via GetGoodsPageList
    description: Detects attempts to exploit CVE-2026-119656 by identifying SQL injection characters and keywords in the order parameter of the api/Agent/GetGoodsPageList endpoint
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to web application firewalls or WAF-enabled SIEM pipelines
      owner: Detection Engineering
      due: 48h
      evidence: Rule targets the CVE-2026-119656 vulnerability
  hunt_leads:
    - lead: Search web access logs for high-frequency or anomalous characters in the order parameter of the specified endpoint
      technique_id: T1190
      data_needed:
        - Web access logs (cs-uri-query)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows boolean-based or time-based blind SQL injection
  mitigation_plan:
    - priority: immediate
      action: Upgrade CoreShop to a patched version once released by CoreUnion
      owner: IT Operations
      addresses: CVE-2026-119656
      evidence: CoreShop through 1.5.5 is the affected version range
---

CoreShop by CoreUnion through 1.5.5 is susceptible to an unauthenticated SQL injection vulnerability. The flaw exists in the 'api/Agent/GetGoodsPageList' endpoint, where the 'order' parameter is insecurely concatenated into an 'ORDER BY' clause. This allows unauthenticated attackers to manipulate the query structure, bypassing field validation implemented in SqlSugar.

## Impact
Attackers can leverage boolean-based or time-based blind SQL injection to extract sensitive information from the application database, including member account credentials and order history details.

## Recommendation
- Upgrade CoreShop to a version beyond 1.5.5 immediately upon release of a vendor patch.
- Inspect web server access logs for anomalous requests to 'api/Agent/GetGoodsPageList' containing special characters commonly associated with SQL injection (e.g., semicolons, dashes, or time-delay functions like 'SLEEP' or 'WAITFOR DELAY').
- Apply WAF rules to block or sanitize 'order' parameters directed at the 'api/Agent/GetGoodsPageList' endpoint that contain non-alphanumeric characters or SQL keywords.
