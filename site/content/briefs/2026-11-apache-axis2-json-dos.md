---
brief_id: brief-2026-11-06-apache-axis2-json-dos
event_id: brief-2026-11-06-apache-axis2-json-dos
revision: 3
activity_at: "2026-11-12T22:17:30Z"
revision_history:
  - revision: 2
    at: "2026-11-09T15:52:52Z"
    checksum: sha256:db866bfbff33a1303d9a99888946a783933b37a5eb200687096a627ce77dfa4f
    summary: new product
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120367
  - revision: 3
    at: "2026-11-12T22:17:30Z"
    checksum: sha256:9c846bd658467b3ea4844c5ae94bd703f7363f0071af24465bf9b7f8e643fcee
    summary: added coverage for Axis2
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - priority_signals
      - references
      - severity
      - tags
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4536
title: 'Apache Axis2/Java: Unbounded JSON request body memory exhaustion (CVE-2026-120367)'
slug: 2026-11-apache-axis2-json-dos
description: Apache Axis2/Java versions prior to 2.0.2 are vulnerable to a denial-of-service condition where unauthenticated attackers can exhaust server memory by sending large, unbounded JSON requests.
date: "2026-11-06T19:23:03Z"
lastmod: "2026-11-12T22:16:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:apache:axis2:*:*:*:*:*:java:*:*
tags:
  - denial-of-service
  - web-application
vendors:
  - Apache
products:
  - Axis2/Java (< 2.0.2)
  - Axis2/Java (<= 2.0.1)
  - Axis2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: an unauthenticated caller could exhaust server memory with a large JSON request
    confidence_band: high
cves:
  - id: CVE-2026-120367
    cvss: 7.5
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/560
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120367
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4536
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all internal and external-facing Apache Axis2 deployments
      owner: IT Operations
      due: 48h
  hunt_leads:
    - lead: Monitor for abnormally large HTTP POST request sizes directed at JSON parsing endpoints
      data_needed:
        - Web server access logs with Content-Length field
      priority: low
      confidence: medium
      disposition: convert_to_detection
      evidence: buffered the entire request body with no size limit
    - lead: Identify unusual traffic spikes or error rates targeting Axis2 service endpoints
      data_needed:
        - Web server access logs
        - Application performance monitoring metrics
      priority: medium
      confidence: low
      disposition: hunt_now
      evidence: Source identifies potential for remote anonymous DoS attacks.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Axis2/Java to version 2.0.2 or later
      owner: IT Operations
      addresses: CVE-2026-120367
      evidence: Version 2.0.2 bounds JSON request bodies with the configurable...
updates:
  - at: "2026-11-09T15:52:02Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120367
  - at: "2026-11-12T22:16:02Z"
    level: L2
    summary: added coverage for Axis2
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4536
---

Apache Axis2/Java versions before 2.0.2 contain an "Allocation of Resources Without Limits or Throttling" vulnerability. The JSON message builders, specifically the Gson, Moshi, and HTTP/2 variants, buffer the entire request body into memory without size constraints. An unauthenticated attacker can exploit this behavior by sending a specially crafted, excessively large JSON request to the server, resulting in memory exhaustion and a potential denial-of-service (DoS) condition. Version 2.0.2 introduces configurable limits to mitigate this risk.

## Impact

The primary risk is a denial-of-service condition caused by heap memory exhaustion, which can crash the JVM or cause severe performance degradation for the affected service.

## Recommendation

* Upgrade Apache Axis2/Java to version 2.0.2 or later to enable configurable request body size limits.
* Implement upstream request size restrictions at the WAF or reverse proxy layer to drop excessively large HTTP POST requests before they reach the Axis2 service.
