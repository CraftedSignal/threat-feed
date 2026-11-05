---
brief_id: brief-2026-11-05-keycloak-dos
event_id: brief-2026-11-05-keycloak-dos
revision: 1
activity_at: "2026-11-05T18:23:00Z"
title: 'Keycloak: Disk space exhaustion denial-of-service in theme resource endpoint (CVE-2026-110932)'
slug: 2026-11-keycloak-dos
description: Keycloak is vulnerable to a denial-of-service condition where an unauthenticated attacker can exhaust disk space by providing arbitrary theme names that trigger persistent on-disk gzip cache creation.
date: "2026-11-05T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - low
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
  - cpe:2.3:a:keycloak:keycloak:*:*:*:*:*:*:*:*
vendors:
  - Keycloak
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can exploit this by sending many requests with unique, fabricated theme names, leading to persistent disk space exhaustion that survives server restarts and causes service disruptions.
    confidence_band: high
cves:
  - id: CVE-2026-110932
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110932
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify all Keycloak deployments and verify if they are internet-facing
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110932 exposes the theme resource endpoint to unauthenticated attackers.
  hunt_leads:
    - lead: Monitor for high volumes of web requests to theme-related endpoints with randomized or unique query parameters in access logs.
      technique_id: T1499
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated attacker can exploit this by sending many requests with unique, fabricated theme names.
  mitigation_plan:
    - priority: immediate
      action: Apply available security patches for Keycloak and configure WAF rules to filter requests to the theme resource endpoint
      owner: IT Operations
      addresses: CVE-2026-110932
      evidence: The issue occurs because the server fails to validate theme names before using them as keys for an on-disk gzip cache.
---

A vulnerability in the theme resource endpoint of Keycloak allows unauthenticated attackers to cause a denial-of-service via disk space exhaustion. The vulnerability exists because the server fails to properly validate theme names before using them as keys for an on-disk gzip cache. By submitting a high volume of requests with unique, fabricated theme names, an attacker can force the application to cache these as distinct files on the server's disk. This cache persists across service restarts, potentially leading to system-wide disk space depletion and service disruption.

## Impact

Successful exploitation results in service unavailability due to disk space exhaustion. The cached files persist across server reboots, requiring manual cleanup of the storage directory to restore service functionality.

## Recommendation

* Inventory all instances of Keycloak to identify exposed theme resource endpoints.
* Monitor disk usage on servers hosting Keycloak for rapid, anomalous growth in cache or temporary storage directories.
* Apply security patches provided by the Keycloak project as soon as they become available to address input validation failures at the theme resource endpoint.
* Restrict access to the theme resource endpoint via network-level controls or a web application firewall (WAF) if immediate patching is not possible.
