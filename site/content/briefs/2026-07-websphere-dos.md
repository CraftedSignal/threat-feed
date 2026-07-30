---
title: Denial of Service Vulnerability in IBM WebSphere Application Server - Liberty
slug: 2026-07-websphere-dos
description: A remote unauthenticated denial-of-service vulnerability in IBM WebSphere Application Server - Liberty allows attackers to cause excessive memory consumption via crafted requests.
date: "2026-07-30T15:31:34Z"
lastmod: "2026-07-30T15:31:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - vulnerability
  - web-server
  - web-application
  - csrf
  - ssrf
  - privilege-escalation
vendors:
  - IBM
products:
  - WebSphere Application Server - Liberty
cves:
  - id: CVE-2026-11897
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11897
  - https://www.ibm.com/support/pages/node/7280695
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14980
  - https://www.ibm.com/support/pages/node/7281651
updates:
  - at: "2026-07-30T15:31:53Z"
    level: L2
    summary: 'merged source coverage: CSRF to SSRF Vulnerability in IBM WebSphere Application Server Liberty'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-14980
---

IBM WebSphere Application Server - Liberty versions 17.0.0.3 through 26.0.0.7 contain a vulnerability identified as CVE-2026-11897. This issue is categorized under CWE-770 (Allocation of Resources Without Limits or Throttling). A remote, unauthenticated attacker can exploit this flaw by sending a specially crafted request to the application server. The vulnerability allows the attacker to trigger uncontrolled memory consumption, which may result in a denial-of-service condition, service instability, or system-wide resource exhaustion. This affects deployments of the Liberty profile across various environments, as the flaw resides within the request handling logic of the server. Defenders should identify vulnerable versions in their environment and prioritize applying patches provided by IBM to prevent resource exhaustion attacks.

## Impact

The vulnerability poses a significant risk to availability. If successfully exploited, an attacker can crash the application server or degrade its performance, rendering it unavailable to legitimate users. The impact is primarily focused on the stability and uptime of enterprise applications running on the affected versions of the Liberty profile. Given the widespread use of WebSphere in enterprise environments, widespread or targeted exploitation could lead to significant business disruption.

## Recommendation

1. Identify all instances of IBM WebSphere Application Server - Liberty within the environment to confirm if they fall within the affected range (17.0.0.3 through 26.0.0.7).
2. Apply the relevant security patches provided by IBM as documented in the vendor advisory (https://www.ibm.com/support/pages/node/7280695).
3. Monitor web server and application logs for unusual request patterns, such as abnormally large payloads or repeated requests originating from a single source that correlate with memory spikes or process restarts.
4. Implement rate limiting and request size limits at the load balancer or reverse proxy level to mitigate the impact of potentially malicious crafted requests.
