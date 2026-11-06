---
brief_id: brief-2026-11-06-apache-axis2-json-dos
event_id: brief-2026-11-06-apache-axis2-json-dos
revision: 1
activity_at: "2026-11-06T19:23:03Z"
title: 'Apache Axis2/Java: Unbounded JSON request body memory exhaustion (CVE-2026-120367)'
slug: 2026-11-apache-axis2-json-dos
description: Apache Axis2/Java versions prior to 2.0.2 are vulnerable to a denial-of-service condition where unauthenticated attackers can exhaust server memory by sending large, unbounded JSON requests.
date: "2026-11-06T19:23:03Z"
type: advisory
types:
  - advisory
severities:
  - low
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
vendors:
  - Apache
products:
  - Axis2/Java (< 2.0.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: an unauthenticated caller could exhaust server memory with a large JSON request
    confidence_band: high
cves:
  - id: CVE-2026-120367
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/560
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  hunt_leads:
    - lead: Monitor for abnormally large HTTP POST request sizes directed at JSON parsing endpoints
      data_needed:
        - Web server access logs with Content-Length field
      priority: low
      confidence: medium
      disposition: convert_to_detection
      evidence: buffered the entire request body with no size limit
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Axis2/Java to version 2.0.2 or later
      owner: IT Operations
      addresses: CVE-2026-120367
      evidence: Version 2.0.2 bounds JSON request bodies with the configurable...
---

Apache Axis2/Java versions before 2.0.2 contain an "Allocation of Resources Without Limits or Throttling" vulnerability. The JSON message builders, specifically the Gson, Moshi, and HTTP/2 variants, buffer the entire request body into memory without size constraints. An unauthenticated attacker can exploit this behavior by sending a specially crafted, excessively large JSON request to the server, resulting in memory exhaustion and a potential denial-of-service (DoS) condition. Version 2.0.2 introduces configurable limits to mitigate this risk.

## Impact

The primary risk is a denial-of-service condition caused by heap memory exhaustion, which can crash the JVM or cause severe performance degradation for the affected service.

## Recommendation

* Upgrade Apache Axis2/Java to version 2.0.2 or later to enable configurable request body size limits.
* Implement upstream request size restrictions at the WAF or reverse proxy layer to drop excessively large HTTP POST requests before they reach the Axis2 service.
