---
brief_id: brief-2026-11-02-psqlodbc-memory-corruption
event_id: brief-2026-11-02-psqlodbc-memory-corruption
revision: 3
activity_at: "2026-11-02T23:49:13Z"
revision_history:
  - revision: 2
    at: "2026-11-02T21:52:50Z"
    checksum: sha256:2f0d38cab0442c004a65d1b58cef46a79a4c3c7f647120029bc16df5086cb1b7
    summary: added CVE-2026-120065
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120065
  - revision: 3
    at: "2026-11-02T23:49:13Z"
    checksum: sha256:65e11bb4bb099c02e94b7affa6f93086ef65cf7a831ec29b1a21d80cdda7dccd
    summary: added coverage for psqlODBC (< 18.00.0006)
    changed_fields:
      - action_plan
      - affected_vendors
      - cpes
      - cves
      - lastmod
      - qa_status
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120062
title: 'PostgreSQL: psqlODBC memory corruption via large-object read (CVE-2026-120057)'
slug: 2026-11-psqlodbc-memory-corruption
description: The psqlODBC driver is vulnerable to memory corruption during loread operations because it fails to validate server-provided data lengths against buffer sizes.
date: "2026-11-02T19:49:40Z"
lastmod: "2026-11-02T23:48:29Z"
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
  validation_status: Source corroborated; technical details clearly map to CVE-2026-120062
cpes:
  - cpe:2.3:a:postgresql:psqlodbc:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
  - psqlodbc
  - postgresql
  - sql-injection
  - database
vendors:
  - PostgreSQL
products:
  - psqlODBC (versions before 18.00.0006)
  - psqlODBC (< 18.00.0006)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An application that passes an untrusted table or schema name to SQLSpecialColumns lets the caller execute arbitrary SQL with the privileges of the connection.
    confidence_band: high
cves:
  - id: CVE-2026-120057
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-120065
    cvss: 7.1
    kev_status: "false"
  - id: CVE-2026-120062
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120057
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120065
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120062
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications and services using psqlODBC versions prior to 18.00.0006
      owner: IT Operations
      due: 48h
      evidence: Source states versions before 18.00.0006 are affected
  hunt_leads:
    - lead: Search application or database logs for anomalous SQL syntax or unexpected catalog function calls containing non-alphanumeric characters in table/schema arguments
      technique_id: T1190
      data_needed:
        - Application logs
        - Database query logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source states SQLSpecialColumns function is the injection vector
  mitigation_plan:
    - priority: immediate
      action: Upgrade psqlODBC to 18.00.0006 or later
      owner: IT Operations
      addresses: CVE-2026-120062
      evidence: NVD remediation guidance
updates:
  - at: "2026-11-02T21:51:56Z"
    level: L2
    summary: added CVE-2026-120065
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120065
  - at: "2026-11-02T23:48:29Z"
    level: L2
    summary: added coverage for psqlODBC (< 18.00.0006)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120062
---

A memory corruption vulnerability exists in the psqlODBC driver. During large-object read (loread) operations, the driver copies data into the application's buffer using the length provided by the server without comparing it to the actual buffer size. An untrusted server or a man-in-the-middle can provide an excessive length, causing the driver to return more bytes than the buffer can hold, resulting in an overwrite of adjacent memory in the client process. Fetching any large-object column can trigger this condition.
