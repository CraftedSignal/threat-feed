---
brief_id: brief-2026-11-03-xwiki-info-disclosure
event_id: brief-2026-11-03-xwiki-info-disclosure
revision: 2
activity_at: "2026-11-09T13:36:23Z"
revision_history:
  - revision: 2
    at: "2026-11-09T13:36:23Z"
    checksum: sha256:10fea5966868430e0d6cdcb2d075e7e9f09da2228f74d5bb4019ede9cd656e7d
    summary: severity → critical; added CVE-2025-32429
    changed_fields:
      - action_plan
      - affected_products
      - content
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - rules
      - severity
      - summary
      - title
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BYTEREAPER77-CVE-2025-32429&utm_source=rss&utm_medium=rss
title: 'XWiki Platform: Blind SQL injection in getdeleteddocuments.vm (CVE-2025-32429)'
slug: 2026-11-xwiki-info-disclosure
description: CVE-2025-32429 is a critical blind SQL injection vulnerability in the XWiki LiveData REST API allowing unauthenticated attackers to extract database contents via the sort parameter in getdeleteddocuments.vm.
date: "2026-11-03T15:42:38Z"
lastmod: "2026-11-09T13:35:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "3"
  rating: A3
  likelihood: roughly even chance
qa_status:
  verdict: pass_with_fixes
  validation_status: Awaiting vendor release for patch validation
cpes:
  - cpe:2.3:a:xwiki:xwiki:*:*:*:*:*:*:*:*
vendors:
  - XWiki
products:
  - XWiki
  - XWiki Platform (< 16.10.6, 17.2.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Blind SQL injection exists in the XWiki LiveData REST API at the getdeleteddocuments.vm endpoint.
    confidence_band: high
cves:
  - id: CVE-2025-32429
    cvss: 9.8
    epss: 0.85496
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4300
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BYTEREAPER77-CVE-2025-32429
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BYTEREAPER77-CVE-2025-32429&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2025-32429 Exploitation - SQL Injection in getdeleteddocuments.vm
    description: Detects attempts to exploit CVE-2025-32429 by checking for common SQL injection keywords in the sort parameter of the getdeleteddocuments.vm endpoint.
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
  priority: monitor_or_close
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory XWiki instances within the environment
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists in XWiki.
    - action: Patch all XWiki instances to version 16.10.6, 17.2.2 or later
      owner: IT Operations
      due: 24h
      evidence: Official patch versions provided in the advisory
  enrichment_needed:
    - item: Vulnerability technical details and affected versions
      owner: CTI
      reason: Necessary to scope the risk and identify which instances require patching.
      evidence: BSI notice lacks detail on affected versions.
  hunt_leads:
    - lead: Search web server access logs for anomalous, repetitive GET requests directed at sensitive API or configuration paths.
      data_needed:
        - webserver access logs
      priority: medium
      confidence: low
      disposition: monitor_or_close
      evidence: Vulnerability allows remote information disclosure.
    - lead: Identify unauthorized access to getdeleteddocuments.vm
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source indicates active exploitation via this endpoint
  mitigation_plan:
    - priority: immediate
      action: Monitor vendor advisory for release of patched version and upgrade accordingly.
      owner: IT Operations
      addresses: XWiki information disclosure vulnerability
      evidence: Standard remediation for vendor-supplied software vulnerabilities.
    - priority: immediate
      action: Upgrade XWiki software
      owner: IT Operations
      addresses: CVE-2025-32429
      evidence: Official vendor remediation advice
updates:
  - at: "2026-11-09T13:35:50Z"
    level: L3
    summary: severity → critical; added CVE-2025-32429
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BYTEREAPER77-CVE-2025-32429&utm_source=rss&utm_medium=rss
---

CVE-2025-32429 is a blind SQL injection vulnerability identified in the XWiki LiveData REST API. The vulnerability exists within the 'sort' parameter of the 'getdeleteddocuments.vm' endpoint. Unauthenticated attackers can leverage this flaw to perform time-based or UNION-based SQL injection, potentially leading to unauthorized data exfiltration from the underlying database. The vulnerability has been confirmed with a CVSS score of 9.8.

## Attack Chain
1. Reconnaissance: Attacker identifies a target instance of XWiki.
2. WAF Detection: The exploit tool sends a test payload with a "sqlmap" User-Agent to identify if a WAF is present.
3. Injection: Attacker sends a crafted HTTP request to 'getdeleteddocuments.vm' containing SQL payloads in the 'sort' parameter.
4. Execution: The XWiki application processes the unsanitized input within the database query.
5. Data Exfiltration: Attacker interprets application response times (time-based) or injected content (UNION-based) to reconstruct database records.

## Impact
Successful exploitation allows unauthenticated attackers to query the database, potentially leading to full compromise of the instance's data.

## Recommendation
- Upgrade all XWiki Platform instances to version 16.10.6 or 17.2.2 or later to address the vulnerability in 'getdeleteddocuments.vm'.
- Monitor web server logs for requests to 'getdeleteddocuments.vm' containing SQL metacharacters (e.g., 'SLEEP', 'UNION', 'SELECT') in the query parameters.
- Implement strict input validation or use an allowlist for the 'sort' parameter to restrict accepted inputs to authorized field names.
