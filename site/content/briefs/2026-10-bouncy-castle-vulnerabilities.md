---
title: Multiple Vulnerabilities in Bouncy Castle for Java
slug: 2026-10-bouncy-castle-vulnerabilities
description: Bouncy Castle for Java is affected by multiple vulnerabilities that allow remote attackers to perform privilege escalation, security bypass, data manipulation, information disclosure, or denial-of-service.
date: "2026-10-05T18:42:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bouncy_castle:for_java:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - java
  - cryptography
vendors:
  - Bouncy Castle
products:
  - Bouncy Castle for Java (< 1.78)
cves:
  - id: CVE-2024-29857
    cvss: 7.5
    epss: 0.011
  - id: CVE-2024-30171
    cvss: 5.9
    epss: 0.00901
  - id: CVE-2024-30172
    cvss: 7.5
    epss: 0.00753
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3726
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all Java applications for dependencies on Bouncy Castle library versions
      owner: Application Security
      due: 48h
      evidence: Source reporting of multiple vulnerabilities in Bouncy Castle for Java
  mitigation_plan:
    - priority: immediate
      action: Patch Bouncy Castle for Java to 1.78 or later
      owner: IT Operations
      addresses: CVE-2024-29857, CVE-2024-30171, CVE-2024-30172
      evidence: Source documentation of multiple vulnerabilities
---

Bouncy Castle for Java is affected by several critical vulnerabilities, identified as CVE-2024-29857, CVE-2024-30171, and CVE-2024-30172. These security flaws allow a remote, unauthenticated attacker to manipulate cryptographic operations, bypass security controls, and disclose sensitive information or cause a denial-of-service (DoS) state. Because Bouncy Castle is a widely deployed cryptographic library used by numerous enterprise Java applications, these vulnerabilities represent a significant risk for systems relying on its underlying providers for TLS, data signing, and object serialization. Defenders must assess their application inventory to identify dependencies on the vulnerable versions and coordinate updates with application development teams.

## Impact

Successful exploitation of these vulnerabilities could result in the total compromise of cryptographic integrity within the affected Java applications. This potentially leads to the interception of encrypted communications, unauthorized access to secure data, or the complete disruption of services dependent on these cryptographic primitives.

## Recommendation

- Identify all Java-based applications within the enterprise environment that bundle or depend on Bouncy Castle libraries.
- Review the official Bouncy Castle project release notes to identify the patched library versions for CVE-2024-29857, CVE-2024-30171, and CVE-2024-30172.
- Update all identified vulnerable application components to the latest patched releases of Bouncy Castle.
- Perform dependency scans using Software Bill of Materials (SBOM) or SCA tooling to ensure no transitive dependencies include the vulnerable Bouncy Castle binaries.
