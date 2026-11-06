---
brief_id: brief-2026-11-04-devolutions-server-vulnerabilities
event_id: brief-2026-11-04-devolutions-server-vulnerabilities
revision: 2
activity_at: "2026-11-06T21:30:22Z"
revision_history:
  - revision: 2
    at: "2026-11-06T21:30:22Z"
    checksum: sha256:112da6cf065011775bbad8db2e64443f22bd564ed5ad0ebc6acb13bd3e0881a2
    summary: added CVE-2026-119636; OS windows server
    changed_fields:
      - affected_os
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119636
title: 'Devolutions Server: Multiple security vulnerabilities'
slug: 2026-11-devolutions-server-vulnerabilities
description: The BSI has reported multiple vulnerabilities in Devolutions Server that may allow an attacker to perform unauthorized information disclosure and bypass security controls.
date: "2026-11-04T10:14:42Z"
lastmod: "2026-11-06T21:29:39Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation once patches are released
cpes:
  - cpe:2.3:a:devolutions:server:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - security-advisory
vendors:
  - Devolutions
products:
  - Devolutions Server
affected_os:
  - Windows Server
cves:
  - id: CVE-2026-119636
    cvss: 8.8
    epss: 0.00183
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4306
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119636
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and inventory all Devolutions Server instances
      owner: IT Operations
      due: 24h
      evidence: BSI reported multiple vulnerabilities in Devolutions Server requiring remediation.
  hunt_leads:
    - lead: Monitor web server access logs for anomalous request patterns targeting management or administrative endpoints
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerabilities allow for unauthorized information disclosure and security bypass.
  mitigation_plan:
    - priority: immediate
      action: Monitor for and apply upcoming security updates from Devolutions
      owner: IT Operations
      addresses: Devolutions Server vulnerabilities
      evidence: BSI advisory reports vulnerabilities in Devolutions Server.
updates:
  - at: "2026-11-06T21:29:39Z"
    level: L2
    summary: added CVE-2026-119636; OS windows server
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119636
---

The German Federal Office for Information Security (BSI) has disclosed the existence of multiple vulnerabilities affecting Devolutions Server. These flaws enable an attacker to perform information disclosure and bypass established security protections. At this time, specific technical details, CVE identifiers, and mitigation versions remain undisclosed in the BSI advisory.

## Recommendation
- Inventory all Devolutions Server instances within the environment.
- Review administrative logs for unauthorized access patterns or unexpected configuration changes.
- Monitor vendor communication channels and the Devolutions security advisory page for the release of security patches.
- Apply security patches immediately upon availability to remediate the identified vulnerabilities.
