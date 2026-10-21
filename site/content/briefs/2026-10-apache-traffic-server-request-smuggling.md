---
brief_id: brief-2026-10-21-apache-traffic-server-request-smuggling
event_id: brief-2026-10-21-apache-traffic-server-request-smuggling
revision: 2
activity_at: "2026-10-21T21:42:20Z"
revision_history:
  - revision: 2
    at: "2026-10-21T21:42:20Z"
    checksum: sha256:61ff65a0ede4fedd6e16dad628351b628b919d41d1ea8a6cf694a84f98ce5c02
    summary: added coverage for Traffic Server (8.0.0 through 8.1.11, 9.0.0 through 9.2.15, 10.0.0 through 10.1.4, 10.2.0)
    changed_fields:
      - affected_products
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111815
title: 'Apache Traffic Server: Request smuggling vulnerability (CVE-2025-31699)'
slug: 2026-10-apache-traffic-server-request-smuggling
description: Apache Traffic Server is vulnerable to request smuggling due to the improper handling of shared origin connections when client request bodies are incomplete, allowing cache poisoning and access control bypass.
date: "2026-10-21T19:58:34Z"
lastmod: "2026-10-21T21:41:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:apache:traffic_server:*:*:*:*:*:*:*:*
tags:
  - request-smuggling
  - vulnerability
  - webserver
  - cache-poisoning
  - cve-2026-111816
  - rce
  - cve-2026-111813
vendors:
  - Apache
products:
  - Traffic Server (8.0.0-8.1.11, 9.0.0-9.2.15, 10.0.0-10.1.4, 10.2.0)
  - Traffic Server
  - Traffic Server (8.0.1 through 8.1.11, 9.0.0 through 9.2.15, 10.0.0 through 10.1.4, 10.2.0)
  - Traffic Server (9.2.15, 10.1.4, 10.2.0)
  - Traffic Server (9.0.0 through 9.2.15, 10.0.0 through 10.1.4, 10.2.0)
  - Traffic Server (8.0.0 through 8.1.11, 9.0.0 through 9.2.15, 10.0.0 through 10.1.4, 10.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The origin reads a later request on that connection as leftover body data, which lets an attacker smuggle requests past ATS access controls.
    confidence_band: high
cves:
  - id: CVE-2025-31699
    cvss: 8.9
    kev_status: "false"
  - id: CVE-2026-111815
    kev_status: unknown
  - id: CVE-2026-111816
    kev_status: unknown
  - id: CVE-2026-111813
    kev_status: unknown
  - id: CVE-2026-111810
    kev_status: unknown
  - id: CVE-2026-111814
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-31699
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111816
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111813
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111810
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111814
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111815
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Traffic Server to 9.2.16, 10.1.5, or 10.2.1
      owner: IT Operations
      addresses: CVE-2025-31699
      evidence: Users are recommended to upgrade to version 9.2.16, 10.1.5, or 10.2.1, which fix the issue.
updates:
  - at: "2026-10-21T19:59:04Z"
    level: L2
    summary: added coverage for Traffic Server
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111816
  - at: "2026-10-21T21:40:22Z"
    level: L2
    summary: added coverage for Traffic Server (8.0.1 through 8.1.11, 9.0.0 through 9.2.15, 10.0.0 through 10.1.4, 10.2.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111813
  - at: "2026-10-21T21:40:45Z"
    level: L1
    summary: added coverage for Traffic Server (9.2.15, 10.1.4, 10.2.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111810
  - at: "2026-10-21T21:41:00Z"
    level: L2
    summary: added coverage for Traffic Server (9.0.0 through 9.2.15, 10.0.0 through 10.1.4, 10.2.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111814
  - at: "2026-10-21T21:41:03Z"
    level: L2
    summary: added coverage for Traffic Server (8.0.0 through 8.1.11, 9.0.0 through 9.2.15, 10.0.0 through 10.1.4, 10.2.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111815
---

Apache Traffic Server (ATS) incorrectly returns an origin connection to the shared pool while the connection is still expecting a request body from the client, including instances involving the 'Expect: 100-continue' header. An attacker can exploit this behavior by sending a partial request, causing the origin to interpret subsequent requests from other users as leftover body data. This allows for request smuggling, potentially leading to unauthorized access, cross-user request disruption, or cache poisoning.

## Impact

Successful exploitation permits an attacker to bypass ATS access controls, intercept or disrupt legitimate user requests, and perform cache poisoning. The vulnerability carries a CVSS v3.1 base score of 8.9.

## Recommendation

Upgrade Apache Traffic Server instances to the patched versions: 9.2.16, 10.1.5, or 10.2.1.
