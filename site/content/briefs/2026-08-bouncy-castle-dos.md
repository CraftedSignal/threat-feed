---
title: Denial of Service Vulnerabilities in Bouncy Castle for Java FIPS
slug: 2026-08-bouncy-castle-dos
description: Multiple vulnerabilities in the Bouncy Castle for Java FIPS library allow remote, anonymous attackers to trigger a denial-of-service condition.
date: "2026-08-10T13:26:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - java
  - library-vulnerability
vendors:
  - Bouncy Castle
products:
  - Bouncy Castle for Java FIPS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in Bouncy Castle for Java FIPS ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2709
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Architecture
  immediate_actions:
    - action: Inventory enterprise Java applications to determine library dependency on Bouncy Castle for Java FIPS.
      owner: IT Operations
      due: 72h
      evidence: Source identifies library-level vulnerabilities requiring remediation.
  mitigation_plan:
    - priority: medium_term
      action: Monitor for and deploy official vendor security updates for Bouncy Castle for Java FIPS.
      owner: IT Operations
      addresses: Bouncy Castle for Java FIPS
      evidence: Source specifies vulnerabilities in Bouncy Castle for Java FIPS.
---

The Bouncy Castle for Java FIPS (Federal Information Processing Standards) library has been identified as containing multiple vulnerabilities that may be exploited by remote, anonymous attackers to cause a denial-of-service (DoS) condition. Bouncy Castle is a widely used set of cryptographic APIs for the Java platform. Successful exploitation of these flaws disrupts the availability of services that rely on this library for cryptographic operations. Because this is a library-level vulnerability, the impact is highly dependent on how the underlying application implements the affected cryptographic components. Defenders should audit applications to identify dependencies on the FIPS-certified Bouncy Castle version and monitor for vendor updates to mitigate the availability risk.

## Impact

Successful exploitation results in a denial-of-service condition for applications leveraging the affected Bouncy Castle for Java FIPS library. This can lead to service outages and the inability of systems to perform essential cryptographic functions, impacting business continuity. The specific number of victims is currently unknown, but the library is pervasive in enterprise Java environments.

## Recommendation

- Perform an inventory of all Java applications to identify those incorporating the Bouncy Castle for Java FIPS library.
- Prioritize patching as soon as the vendor releases security updates for the affected FIPS-certified versions.
- Monitor application logs for abnormal resource consumption or unexpected crash loops (Java stack traces) in cryptographic service modules.
