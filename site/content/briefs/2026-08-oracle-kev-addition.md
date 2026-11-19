---
brief_id: brief-2026-08-24-oracle-kev-addition
event_id: brief-2026-08-24-oracle-kev-addition
revision: 2
activity_at: "2026-11-19T18:13:06Z"
revision_history:
  - revision: 2
    at: "2026-11-19T18:13:06Z"
    checksum: sha256:64ce5eb572125c6cbbb54db68baf914ca2ccbe072f0cbdf5d83540fa1aff3e34
    summary: exploited:true; KEV CVE-2026-21962
    changed_fields:
      - affected_products
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Active Exploitation of Oracle HTTP Server and WebLogic Server Proxy Plug-in
slug: 2026-08-oracle-kev-addition
description: CISA has added CVE-2026-21962 to the Known Exploited Vulnerabilities (KEV) Catalog due to confirmed in-the-wild exploitation of an improper access control vulnerability in Oracle HTTP and WebLogic proxy components.
date: "2026-08-24T19:53:12Z"
lastmod: "2026-11-19T18:12:21Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-08-24T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source confirmed as CISA KEV update
cpes:
  - cpe:2.3:a:oracle:http_server:12.2.1.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:http_server:14.1.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:http_server:14.1.2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:weblogic_server_proxy_plug-in:12.2.1.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:weblogic_server_proxy_plug-in:14.1.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:weblogic_server_proxy_plug-in:14.1.2.0.0:*:*:*:*:*:*:*
has_poc: true
vendors:
  - Oracle
products:
  - HTTP Server
  - Oracle HTTP Server
  - Oracle Weblogic Server
  - Oracle Weblogic Server Proxy Plug-in
  - Weblogic Server Proxy Plug-in
cves:
  - id: CVE-2026-21962
    cvss: 10
    epss: 0.4323
    kev: true
    kev_status: "true"
references:
  - https://www.cisa.gov/news-events/alerts/2026/08/24/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://www.cve.org/CVERecord?id=CVE-2026-21962
  - https://edit.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
  - https://cyber.gc.ca/en/alerts-advisories/oracle-security-advisory-january-2026-quarterly-rollup-av26-042
  - https://www.securityweek.com/cisa-warns-of-exploited-oracle-weblogic-vulnerability/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Oracle HTTP Server and Oracle Weblogic Server for CVE-2026-21962
      owner: IT Operations
      due: 24h
      evidence: CISA KEV Catalog addition requirement per BOD 26-04
updates:
  - at: "2026-08-24T21:46:32Z"
    level: L1
    summary: new product
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-21962
  - at: "2026-08-24T21:55:14Z"
    level: L2
    summary: poc_available
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/oracle-security-advisory-january-2026-quarterly-rollup-av26-042
  - at: "2026-11-19T18:12:21Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-21962
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

CISA has formally added CVE-2026-21962 to its Known Exploited Vulnerabilities (KEV) Catalog, citing active exploitation. The vulnerability affects Oracle HTTP Server and the Oracle WebLogic Server Proxy Plug-in. It is classified as an improper access control vulnerability. Successful exploitation of this vulnerability in proxy components can allow attackers to bypass security restrictions, potentially leading to unauthorized access to downstream application resources or total control of the affected asset. Given the critical position of proxy and load-balancing components in enterprise architectures, this vulnerability represents a significant risk for lateral movement and unauthorized information disclosure. Organizations are advised to prioritize patching according to Binding Operational Directive (BOD) 26-04 requirements.

## Impact

Successful exploitation allows unauthenticated or unauthorized attackers to manipulate requests passing through the Oracle HTTP Server or WebLogic Proxy Plug-in. This can lead to the exposure of sensitive back-end application data, session hijacking, or full remote code execution if combined with other backend weaknesses. The vulnerability is confirmed to be under active exploitation in the wild, necessitating immediate remediation on all internet-facing Oracle infrastructure.

## Recommendation

* Prioritize the application of security patches for CVE-2026-21962 on all internet-facing Oracle HTTP Server and Oracle WebLogic Server instances.
* Audit web access logs for anomalous request patterns targeting the WebLogic Proxy Plug-in (e.g., suspicious URI manipulation or unexpected headers).
* Enforce strict access control policies for the management interfaces of Oracle WebLogic environments.
* Conduct a review of system logs to determine if unauthorized access occurred prior to patch implementation, as outlined in the requirements of BOD 26-04.
