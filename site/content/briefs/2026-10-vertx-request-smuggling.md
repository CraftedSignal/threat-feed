---
brief_id: brief-2026-10-28-vertx-request-smuggling
event_id: brief-2026-10-28-vertx-request-smuggling
revision: 1
activity_at: "2026-10-28T20:24:22Z"
title: 'Eclipse Vert.x: Request smuggling in HTTP/1.x decoder (CVE-2026-102479)'
slug: 2026-10-vertx-request-smuggling
description: Eclipse Vert.x contains a request smuggling vulnerability in its HTTP/1.x decoder (CVE-2026-102479) that can be leveraged for session fixation attacks.
date: "2026-10-28T20:24:22Z"
lastmod: "2026-11-03T16:01:20Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Patch availability needs environment verification.
cpes:
  - cpe:2.3:a:eclipse:vert.x:*:*:*:*:*:*:*:*
  - cpe:2.3:a:eclipse:vert.x:5.2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:eclipse:vertx:*:*:*:*:*:*:*:*
tags:
  - web-application
  - request-smuggling
  - cve-2026-102479
  - web-vulnerability
  - data-leakage
  - application-security
vendors:
  - Eclipse
products:
  - Vert.x
  - Vert.x (4.0.0-4.5.35, 5.0.0-5.2.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows for potential request smuggling attacks, which can lead to session fixation or other downstream security issues.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: A later user's session, or an anonymous caller through the same client, can receive an earlier user's response. Depending on the response this discloses authenticated content or a session cookie, the latter enabling session fixation or hijacking.
    confidence_band: high
cves:
  - id: CVE-2026-102479
    cvss: 5.9
    epss: 0.0027
    kev_status: "false"
  - id: CVE-2026-118489
    cvss: 7.5
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/426
  - https://github.com/eclipse-vertx/vert.x/security/advisories/GHSA-ch7p-g5pm-3gqx
  - https://research.jfrog.com/post/byte-debt-vertx-header-typo-session-fixation/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118489
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
    - Application Security
  immediate_actions:
    - action: Identify all applications using the affected vertx-core library branches.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects three minor release branches of vertx-core.
    - action: Inventory all internal applications utilizing Eclipse Vert.x to identify exposure to CachingWebClient usage.
      owner: Application Security
      due: 48h
      evidence: CVE-2026-118489 affects Vert.x CachingWebClient implementations.
  hunt_leads:
    - lead: Audit access logs for authenticated HTTP responses lacking private/no-store headers that are subsequently accessed by different user sessions within the same application process.
      technique_id: T1539
      data_needed:
        - Application-level access logs
        - Response header metadata
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The flaw relies on caching cacheable responses not marked private/no-store.
  mitigation_plan:
    - priority: immediate
      action: Upgrade vulnerable Vert.x applications to the patched release branch version.
      owner: IT Operations
      addresses: CVE-2026-102479
      evidence: Vendor security advisory GHSA-ch7p-g5pm-3gqx.
    - priority: medium
      action: Implement strict Cache-Control headers (private, no-store) on all authenticated endpoints to prevent improper caching.
      owner: IT Operations
      addresses: CVE-2026-118489
      evidence: NVD vulnerability disclosure indicates responses not marked private/no-store are susceptible.
updates:
  - at: "2026-11-03T16:01:20Z"
    level: L2
    summary: added coverage for Vert.x (4.0.0-4.5.35, 5.0.0-5.2.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-118489
---

A request smuggling vulnerability has been identified in the Eclipse Vert.x HTTP/1.x decoder, tracked as CVE-2026-102479. The vulnerability arises from how the library handles specific HTTP header patterns, potentially allowing an attacker to manipulate request interpretation. This flaw can lead to downstream impacts, including session fixation. The vulnerability affects three specific minor release branches of the vertx-core component.

## Impact
Successful exploitation may allow attackers to perform request smuggling, which can lead to session fixation or other unauthorized operations depending on the architecture of the application utilizing the affected Vert.x component.

## Recommendation
- Inventory applications utilizing vertx-core to determine if they are running on the affected minor release branches.
- Prioritize patching by upgrading to the secure version of Vert.x released by the vendor in response to GHSA-ch7p-g5pm-3gqx.
- Review application logic for dependencies on header integrity if upgrading is not immediately feasible.
