---
brief_id: brief-2026-10-camel-as2-signing-confusion
event_id: brief-2026-10-camel-as2-signing-confusion
revision: 1
activity_at: "2026-10-20T11:33:10Z"
title: 'Apache Camel: AS2 MDN signing key confusion (CVE-2026-85296)'
slug: 2026-10-camel-as2-signing-confusion
description: CVE-2026-85296 allows cross-partner signing key leakage in Apache Camel AS2 deployments due to improper state management of per-request keys in shared instance fields.
date: "2026-10-20T11:33:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - camel-as2
  - cve-2026-85296
  - vulnerability
  - as2
vendors:
  - Apache
products:
  - camel-as2 (4.0.0-4.18.4, 4.19.0-4.22.0)
  - camel-spring-boot (3.5.13)
  - camel-quarkus-as2
cves:
  - id: CVE-2026-85296
    cvss: 6.5
    kev_status: unknown
references:
  - https://camel.apache.org/security/CVE-2026-85296.html
  - https://sploitus.com/exploit?id=EBF6D562-387E-5E90-A216-E528CD447577
  - https://issues.apache.org/jira/browse/CAMEL-24429
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all instances of camel-as2 to version 4.18.5, 4.22.1, or 4.23.0
      owner: IT Operations
      due: 72h
      evidence: Vulnerability summary identifies 4.18.5, 4.22.1, and 4.23.0 as fixed versions
  mitigation_plan:
    - priority: short_term
      action: Separate Camel context configurations per trading partner to prevent signing key sharing
      owner: IT Operations
      addresses: CVE-2026-85296
      evidence: Source advises running a separate Camel context per trading partner if upgrade is not possible
---

CVE-2026-85296 is a vulnerability within the `camel-as2` component of Apache Camel (versions 4.0.0 to 4.18.4 and 4.19.0 to 4.22.0) that permits cross-partner signing key confusion during the processing of AS2 (Applicability Statement 2) messages. The vulnerability stems from the `ResponseMDN` class, which incorrectly stores per-request signing material in a shared instance field. In multi-partner AS2 deployments, where a single `ResponseMDN` instance serves concurrent requests, the private key resolved for one trading partner can be overwritten or accessed by a subsequent or concurrent request from a different partner. Consequently, an AS2 Message Disposition Notification (MDN) may be signed using the private key of the incorrect trading partner. This vulnerability is triggered by legitimate concurrent AS2 traffic and does not require complex delivery mechanisms.

## Attack Chain

1. The target deploys a multi-partner AS2 interface using the affected `camel-as2` component.
2. The application registers a single shared `ResponseMDN` instance on the `HttpProcessor` to handle incoming AS2 requests.
3. Partner A initiates an AS2 request, and the system resolves Partner A's signing material into the `ResponseMDN` instance.
4. The `camel-as2` component writes this per-request private key into an instance field of the shared `ResponseMDN` object.
5. Partner B initiates a concurrent or subsequent AS2 request before the previous operation concludes or cleans up.
6. The `ResponseMDN` instance processes the request for Partner B, potentially reading the signing key stored in the instance field that still holds Partner A's material.
7. The application generates an MDN for Partner B that is cryptographically signed using the private key belonging to Partner A.

## Impact

Successful exploitation results in the signing of MDN responses with the incorrect trading partner's private key. This compromise of cryptographic integrity impacts non-repudiation and authentication within AS2 communication, potentially allowing misrouting of signed receipts or business logic disruption between trading partners. The vulnerability affects multi-partner AS2 environments, including those utilizing Camel Spring Boot and Camel Quarkus implementations.

## Recommendation

1. Upgrade to Apache Camel 4.18.5, 4.22.1, or 4.23.0 to resolve the state management flaw in `ResponseMDN`.
2. If an immediate upgrade is not feasible, re-architect the Camel deployment to utilize a separate Camel context for each trading partner to ensure isolation of signing material.
3. Verify the fix by monitoring application logs for signing key resolution behavior; the fixed version resolves material into local variables rather than shared instance fields.
