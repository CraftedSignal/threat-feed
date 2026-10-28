---
brief_id: brief-2026-10-28-advantech-sql-injection
event_id: brief-2026-10-28-advantech-sql-injection
revision: 1
activity_at: "2026-10-28T13:02:26Z"
title: Advantech IoTSuite and IoT Edge SQL injection (CVE-2025-52694)
slug: 2026-10-advantech-sql-injection
description: CVE-2025-52694 is a critical unauthenticated SQL injection vulnerability in Advantech IoTSuite and IoT Edge products that allows remote database manipulation and potential code execution.
date: "2026-10-28T13:02:26Z"
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
  - cpe:2.3:a:advantech:iot_edge_linux_docker:*:*:*:*:*:*:*:*
  - cpe:2.3:a:advantech:iot_edge_windows:*:*:*:*:*:*:*:*
  - cpe:2.3:a:advantech:iotsuite_growth_linux_docker:*:*:*:*:*:*:*:*
  - cpe:2.3:a:advantech:iotsuite_saas_composer:*:*:*:*:*:*:*:*
  - cpe:2.3:a:advantech:iotsuite_starter_linux_docker:*:*:*:*:*:*:*:*
tags:
  - sqli
  - vulnerability
  - iot
vendors:
  - Advantech
products:
  - IoTSuite SaaSComposer (< 3.4.15)
  - IoTSuite Growth Linux docker (< 2.0.2)
  - IoTSuite Starter Linux docker (< 2.0.2)
  - IoT Edge Linux docker (< 2.0.2)
  - IoT Edge Windows (< 2.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated critical SQL Injection in Advantech IoTSuite and IoT Edge Products.
    confidence_band: high
cves:
  - id: CVE-2025-52694
    cvss: 10
    epss: 0.39909
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WINZ18-CVE-2025-52694-POC
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WINZ18-CVE-2025-52694-POC&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2025-52694 Exploitation - SQL Injection in Advantech IoTSuite
    description: Detects exploitation attempts against CVE-2025-52694 by identifying suspicious SQL injection patterns within the filename parameter of the /displays/ endpoint
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Advantech IoTSuite and IoT Edge installations and verify version status
      owner: IT Operations
      due: 24h
      evidence: Affected products list includes IoTSuite SaaSComposer, Growth, Starter, and IoT Edge
  hunt_leads:
    - lead: Search web access logs for incoming requests to /displays/ containing 'pg_sleep', 'UNION', or ';'
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technical description mentions exploitation via pg_sleep for verification
  mitigation_plan:
    - priority: immediate
      action: Upgrade to IoTSuite SaaSComposer 3.4.15 or IoTSuite/IoT Edge v2.0.2
      owner: IT Operations
      addresses: CVE-2025-52694
      evidence: Vulnerability fix requirement listed in the source
---

CVE-2025-52694 is a critical vulnerability (CVSS 10.0) affecting multiple Advantech IoTSuite and IoT Edge products. The flaw arises from improper sanitization of the 'filename' parameter in the '/displays/{filename}.json' endpoint, which is directly concatenated into PostgreSQL queries. Unauthenticated attackers can perform stacked queries to extract database information, modify records, or potentially achieve remote code execution depending on database privilege levels. Public exploit scripts and Nuclei templates have been released, elevating the risk of exploitation.

## Impact

Successful exploitation allows unauthenticated attackers to conduct unauthorized database queries, potentially leading to full data compromise, unauthorized modification of sensitive information, and remote code execution on the underlying server.

## Recommendation

- Patch affected instances immediately: Update IoTSuite SaaS Composer to at least 3.4.15 and all other affected IoTSuite/IoT Edge products to version 2.0.2 or later.
- Implement request validation: Ensure that the 'filename' parameter is strictly validated or that parameterized queries are enforced to prevent SQL injection.
- Deploy network monitoring: Use the hunt leads provided to monitor for suspicious pattern matching in URI paths targeting the identified endpoint.
