---
brief_id: brief-2026-10-25-sourcecodester-sqli
event_id: brief-2026-10-25-sourcecodester-sqli
revision: 2
activity_at: "2026-10-29T20:03:29Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:03:29Z"
    checksum: sha256:c91d247a11423a83f5d08e0e5303714b6effc5779875c4209543b919e12c2e97
    summary: 'added detection rule: Detect CVE-2026-116061 Exploitation - SQL Injection in Performance Indicator System'
    changed_fields:
      - action_plan
      - cves
      - lastmod
      - priority_score
      - priority_signals
      - qa_status
      - references
      - rules
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116061
title: 'SourceCodester Performance Indicator System: SQL Injection in Contact argument (CVE-2026-116060)'
slug: 2026-10-sourcecodester-sqli
description: SourceCodester Performance Indicator System 1.0 contains an SQL injection vulnerability in the 'Contact' argument of '/opils/staff/adddealer.php', which can be triggered remotely.
date: "2026-10-25T20:30:02Z"
lastmod: "2026-10-29T20:01:52Z"
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
  validation_status: Rule is ready for deployment but needs environment testing.
cpes:
  - cpe:2.3:a:sourcecodester:performance_indicator_system:*:*:*:*:*:*:*:*
tags:
  - sqli
  - web-vulnerability
vendors:
  - SourceCodester
products:
  - Performance Indicator System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument Contact leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-116060
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-116061
    cvss: 7.3
    epss: 0.00263
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116060
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116061
rules:
  - title: Detect CVE-2026-116061 Exploitation - SQL Injection in Performance Indicator System
    description: Detects exploitation attempts against CVE-2026-116061 by identifying common SQL injection patterns in the Contact parameter of edit_dealer.php
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
    - IT Operations
  immediate_actions:
    - action: Identify and isolate vulnerable instances of Performance Indicator System 1.0.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is remotely exploitable with public exploits available.
  hunt_leads:
    - lead: Search web server logs for anomalous SQL syntax in the Contact parameter of edit_dealer.php
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-uri-query)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Public exploit is available and might be used.
  mitigation_plan:
    - priority: immediate
      action: Apply input sanitization and parameterization on the Contact parameter.
      owner: IT Operations
      addresses: CVE-2026-116061
      evidence: Vulnerability in source code file /opils/staff/edit_dealer.php.
updates:
  - at: "2026-10-29T20:01:52Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-116061 Exploitation - SQL Injection in Performance Indicator System'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116061
---

A vulnerability has been identified in SourceCodester Performance Indicator System 1.0. The flaw exists in the '/opils/staff/adddealer.php' file. Manipulation of the 'Contact' argument can lead to SQL injection. The vulnerability can be exploited remotely, and the exploit has been publicly disclosed.
