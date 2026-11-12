---
brief_id: brief-2026-11-10-fortinet-fortianalyzer-vulnerabilities
event_id: brief-2026-11-10-fortinet-fortianalyzer-vulnerabilities
revision: 2
activity_at: "2026-11-12T00:19:34Z"
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
title: 'Fortinet FortiAnalyzer: Multiple vulnerabilities'
slug: 2026-11-fortinet-fortianalyzer-vulnerabilities
description: The BSI reports multiple vulnerabilities in Fortinet FortiAnalyzer that allow remote, unauthenticated attackers to execute arbitrary code, disclose sensitive information, bypass security controls, and perform cross-site scripting (XSS) attacks.
date: "2026-11-10T16:30:06Z"
lastmod: "2026-11-12T00:16:11Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - vulnerability
  - network-security
  - fortinet
vendors:
  - Fortinet
products:
  - FortiAnalyzer
  - FortiAnalyzer (8.0.0 through 8.0.2)
  - FortiAnalyzer (7.6.0 through 7.6.7)
  - FortiAnalyzer Cloud (8.0.1 through 8.0.2)
  - FortiAnalyzer Cloud (7.6.0 through 7.6.7)
  - FortiAnalyzer-BigData (7.6.0 through 7.6.2)
cves:
  - id: CVE-2026-126170
    cvss: 9.8
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2022-0184
  - https://nvd.nist.gov/vuln/detail/CVE-2026-126170
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
    summary: added CVE-2026-126170; fortianalyzer version 7.6.0 through 7.6.7
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-126170
---

The German Federal Office for Information Security (BSI) has issued an advisory regarding multiple vulnerabilities in Fortinet FortiAnalyzer. These flaws permit unauthenticated remote attackers to perform arbitrary code execution, sensitive information disclosure, security control bypasses, and cross-site scripting (XSS). Specific CVE identifiers were not provided in the source material.

## Recommendation

- Inventory all deployed FortiAnalyzer instances to determine exposure.
- Monitor official Fortinet security advisories for specific patch releases and technical details regarding these vulnerabilities.
- Implement strict network access controls to limit management interface exposure to trusted administrative subnets only.
- Review administrative access logs for unusual activity originating from unexpected IP addresses.
