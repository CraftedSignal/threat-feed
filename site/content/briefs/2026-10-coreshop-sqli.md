---
brief_id: brief-2026-10-30-coreshop-sqli
event_id: brief-2026-10-30-coreshop-sqli
revision: 1
activity_at: "2026-10-30T15:31:28Z"
title: 'CoreShop: Unauthenticated SQL injection in api/Good/GetGoodsPageList (CVE-2026-119655)'
slug: 2026-10-coreshop-sqli
description: CoreShop versions 1.5.5 and earlier contain an unauthenticated SQL injection vulnerability in the api/Good/GetGoodsPageList endpoint, allowing attackers to exfiltrate database contents via the order parameter.
date: "2026-10-30T15:31:28Z"
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
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:coreshop:coreshop:*:*:*:*:*:*:*:*
vendors:
  - CoreShop
products:
  - CoreShop (<= 1.5.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CoreShop through 1.5.5 contains an unauthenticated sql injection vulnerability in the api/Good/GetGoodsPageList endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-119655
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119655
rules:
  - title: Detect CVE-2026-119655 Exploitation - SQL Injection in api/Good/GetGoodsPageList
    description: Detects exploitation attempts targeting CVE-2026-119655 by monitoring for SQL keywords or subquery patterns in the order parameter of the GetGoodsPageList endpoint.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
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
    - action: Deploy Sigma rule to WAF or SIEM for api/Good/GetGoodsPageList monitoring
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-119655 vulnerability in the named endpoint
  hunt_leads:
    - lead: Identify anomalies in request response time for the GetGoodsPageList endpoint which may indicate time-based blind SQLi
      technique_id: T1190
      data_needed:
        - webserver response time latency
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows for time-based blind techniques.
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to sanitize or block requests with suspicious order parameter content
      owner: IT Operations
      addresses: CVE-2026-119655
      evidence: Unsanitized order parameter injection
---

CoreShop versions through 1.5.5 are vulnerable to an unauthenticated SQL injection attack. The vulnerability exists within the 'api/Good/GetGoodsPageList' endpoint, where the 'order' parameter is not properly sanitized before being passed to an SQL ORDER BY clause. An attacker can leverage this flaw to bypass SqlSugar field checks, enabling boolean-based or time-based blind SQL injection to exfiltrate sensitive information, including member accounts and order details.

## Impact
Successful exploitation allows an unauthenticated remote attacker to perform unauthorized database queries, potentially leading to the full exfiltration of application data.

## Recommendation
- Update to a patched version of CoreShop once available, as no fixed version is currently specified.
- Monitor web application logs for suspicious patterns in the 'api/Good/GetGoodsPageList' endpoint, specifically looking for anomalous values in the 'order' parameter containing SQL syntax.
- Implement strict input validation or use a Web Application Firewall (WAF) to block requests containing common SQL injection payloads in the 'order' parameter.
