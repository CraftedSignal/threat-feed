---
brief_id: brief-2026-11-12-curl-vulnerabilities
event_id: brief-2026-11-12-curl-vulnerabilities
revision: 1
activity_at: "2026-11-12T22:16:26Z"
title: 'cURL: Multiple Security Vulnerabilities'
slug: 2026-11-curl-vulnerabilities
description: The German Federal Office for Information Security (BSI) has reported multiple vulnerabilities in cURL that could allow a remote anonymous attacker to cause information disclosure, a denial of service, or other unspecified impacts.
date: "2026-11-12T22:16:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass_with_fixes
  validation_status: Waiting for vendor advisory details to map to specific software versions.
vendors:
  - cURL
products:
  - cURL
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0270
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0270
action_plan:
  priority: enrich_before_decision
  owners:
    - IT Operations
    - CTI
  enrichment_needed:
    - item: Specific CVE identifiers and affected version range for cURL
      owner: CTI
      reason: The BSI notice lacks the specific CVEs required to determine if your organization's deployments are vulnerable.
      evidence: The source document does not list specific CVEs or version numbers.
  mitigation_plan:
    - priority: medium_term
      action: Inventory all systems running cURL and prepare to update to the latest version once the vendor release is confirmed.
      owner: IT Operations
      addresses: cURL installations
      evidence: Standard security practice for vulnerability management when specific CVE data is delayed.
---

The BSI has identified multiple vulnerabilities in cURL. A remote, anonymous attacker could exploit these flaws to perform information disclosure, trigger a denial-of-service (DoS) condition, or achieve other currently unspecified impacts. No specific CVE identifiers were provided in the initial notice. Users are advised to monitor the vendor release channels for updates.
