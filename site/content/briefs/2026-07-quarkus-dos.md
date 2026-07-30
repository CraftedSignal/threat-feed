---
title: Denial of Service Vulnerability in IBM Enterprise Build of Quarkus
slug: 2026-07-quarkus-dos
description: A resource exhaustion vulnerability (CVE-2026-16308) in IBM Enterprise Build of Quarkus allows remote, unauthenticated attackers to cause a denial of service via unbounded accumulation of multipart MIME headers.
date: "2026-07-30T15:32:00Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - IBM
products:
  - Enterprise Build of Quarkus
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Quarkus REST could allow a remote attacker to cause a denial of service due to unbounded accumulation of multipart MIME part-header bytes.
    confidence_band: high
cves:
  - id: CVE-2026-16308
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16308
  - https://www.ibm.com/support/pages/node/7281904
---

IBM Enterprise Build of Quarkus versions 3.27.1 through 3.27.4.SP2 and 3.33.1 through 3.33.2.SP2 are susceptible to a denial of service vulnerability identified as CVE-2026-16308. The flaw exists within the REST component, specifically concerning how the application handles multipart MIME part-header bytes. Due to improper resource management (CWE-770), the system fails to apply necessary limits or throttling when processing these headers. An attacker can exploit this by sending maliciously crafted multipart requests designed to force the server into an unbounded accumulation of these bytes, leading to exhaustion of memory or CPU resources and causing the service to become unresponsive. This vulnerability is remotely exploitable without authentication, presenting a significant risk to the availability of affected enterprise applications.

## Attack Chain

1. Attacker identifies an internet-facing application running a vulnerable version of IBM Enterprise Build of Quarkus.
2. Attacker crafts a custom HTTP request using the multipart/form-data content type.
3. The request is engineered to contain a disproportionately large amount of MIME part-header data per request or a flood of such requests.
4. The Quarkus REST endpoint receives the malformed request.
5. The application's parser fails to enforce size constraints or throttling on the incoming header bytes during the multipart parsing stage.
6. The server continues to allocate resources (memory/CPU) to store or process the unbounded header byte stream.
7. Exhaustion of system resources results in a crash or hung state, effectively performing a denial of service on the target application.

## Impact

Successful exploitation of this vulnerability results in a denial of service, rendering the vulnerable enterprise applications unavailable to legitimate users. Given the nature of the resource exhaustion (CWE-770), this can lead to service instability, application crashes, and potential impacts on other services sharing the same underlying infrastructure. Any organization utilizing the affected IBM Enterprise Build of Quarkus versions in internet-facing configurations is at risk of service disruption.

## Recommendation

Prioritized actions for detection and remediation:
- Upgrade to a patched version of IBM Enterprise Build of Quarkus as specified in the IBM security advisory (https://www.ibm.com/support/pages/node/7281904).
- Implement request body size limits and timeout configurations on front-end reverse proxies or Web Application Firewalls (WAF) to mitigate the impact of malicious multipart MIME traffic.
- Monitor web server logs for a spike in HTTP POST requests with unusually large headers or anomalous multipart/form-data sizes, which may indicate exploitation attempts against CVE-2026-16308.
