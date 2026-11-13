---
brief_id: brief-2026-11-10-fortinet-fortianalyzer-vulnerabilities
event_id: brief-2026-11-10-fortinet-fortianalyzer-vulnerabilities
revision: 4
activity_at: "2026-11-13T06:03:46Z"
revision_history:
  - revision: 2
    at: "2026-11-12T00:19:34Z"
    checksum: sha256:e9a03b45023f418096763c821114a9ef70e412fc33728170ae99944786e21dcc
    summary: added CVE-2026-126170; fortianalyzer version 7.6.0 through 7.6.7
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-126170
  - revision: 3
    at: "2026-11-12T06:14:33Z"
    checksum: sha256:a705bd2652c352ce2891a259650b2c0080f2fe6d541d0d907d8b21d796a1a12f
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=46C078BC-491D-5D7F-9DBC-E9CADAE8846F&utm_source=rss&utm_medium=rss
  - revision: 4
    at: "2026-11-13T06:03:46Z"
    checksum: sha256:4908d3cf91559c3960e561471897cf0988c341eabb88d0448b38a5d92c51870d
    summary: severity → critical
    changed_fields:
      - affected_products
      - content
      - cves
      - lastmod
      - poc_references
      - priority
      - priority_score
      - priority_signals
      - references
      - severity
      - summary
      - title
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=8CDBB615-6341-5929-9362-1C625FCEDA75&utm_source=rss&utm_medium=rss
title: Public PoC Exploit Available for CVE-2026-126170
slug: 2026-11-fortinet-fortianalyzer-vulnerabilities
description: Public proof-of-concept exploit code is available for CVE-2026-126170, a critical vulnerability affecting the FortiManager and FortiAnalyzer JSON-RPC API.
date: "2026-11-10T16:30:06Z"
lastmod: "2026-11-13T06:03:12Z"
type: advisory
claim_state: <nil>
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
  likelihood: roughly even chance
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=46C078BC-491D-5D7F-9DBC-E9CADAE8846F&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=8CDBB615-6341-5929-9362-1C625FCEDA75&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - network-security
  - fortinet
vendors:
  - Fortinet
products:
  - FortiAnalyzer
  - FortiAnalyzer Cloud
  - FortiAnalyzer-BigData
  - FortiManager
product_versions:
  - product: FortiAnalyzer
    range: 7.6.0 through 7.6.7
  - product: FortiAnalyzer
    range: 8.0.0 through 8.0.2
  - product: FortiAnalyzer Cloud
    range: 7.6.0 through 7.6.7
  - product: FortiAnalyzer Cloud
    range: 8.0.1 through 8.0.2
  - product: FortiAnalyzer-BigData
    range: 7.6.0 through 7.6.2
cves:
  - id: CVE-2026-126170
    cvss: 9.8
    epss: 0.00628
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2022-0184
  - https://nvd.nist.gov/vuln/detail/CVE-2026-126170
  - https://sploitus.com/exploit?id=46C078BC-491D-5D7F-9DBC-E9CADAE8846F&utm_source=rss&utm_medium=rss
  - https://cyber.gc.ca/en/alerts-advisories/fortinet-security-advisory-av26-1145
  - https://sploitus.com/exploit?id=8CDBB615-6341-5929-9362-1C625FCEDA75
  - https://sploitus.com/exploit?id=8CDBB615-6341-5929-9362-1C625FCEDA75&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory FortiAnalyzer deployments and review access logs for unauthorized attempts
      owner: SOC
      due: 24h
      evidence: BSI reported vulnerabilities allowing unauthenticated remote access.
  hunt_leads:
    - lead: Identify unauthenticated access attempts to FortiAnalyzer administrative interfaces
      data_needed:
        - FortiAnalyzer device audit logs
        - Firewall access logs for management traffic
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Advisory notes potential for unauthenticated remote exploitation.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches or updates as soon as they are made available by Fortinet
      owner: IT Operations
      addresses: FortiAnalyzer vulnerabilities
      evidence: BSI advisory indicates vulnerability to arbitrary code execution.
updates:
  - at: "2026-11-12T00:16:11Z"
    level: L2
    summary: added CVE-2026-126170;
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-126170
  - at: "2026-11-12T06:12:45Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=46C078BC-491D-5D7F-9DBC-E9CADAE8846F&utm_source=rss&utm_medium=rss
  - at: "2026-11-13T06:03:12Z"
    level: L3
    summary: severity → critical
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=8CDBB615-6341-5929-9362-1C625FCEDA75&utm_source=rss&utm_medium=rss
---

A public proof-of-concept (PoC) exploit for CVE-2026-126170 has been identified on Sploitus. This vulnerability involves improper encoding in the FortiManager and FortiAnalyzer JSON-RPC API, which may allow an unauthenticated attacker to execute code or commands. 

## Impact

The availability of public exploit code increases the potential risk for systems where the JSON-RPC API is enabled on an admin profile.

## Recommendations

Organizations should review the configuration of their Fortinet appliances. The vendor has noted that for the JSON-RPC API flaw, the workaround is to set 'set rpc-permit none' on the admin profile.
