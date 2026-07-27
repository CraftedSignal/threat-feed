---
title: CVE-2026-66730 Denial of Service in facil.io Multipart Body Parser
slug: 2026-07-facilio-dos
description: A denial-of-service vulnerability exists in facil.io versions 0.6.0 through 0.7.6, specifically in its multipart body parser, allowing an unauthenticated remote attacker to permanently freeze worker processes at 100% CPU by sending a malformed multipart/form-data request with a partial closing boundary, effectively disabling the server until manual restart.
date: "2026-07-27T17:18:50Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - web-server
vendors:
  - facil.io
products:
  - facil.io 0.6.0 through 0.7.6
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: An unauthenticated remote attacker to permanently freeze worker processes at 100% CPU by sending a multipart/form-data request with a partial closing boundary. ...exhausting all workers and permanently disabling the server until manually restarted.
    confidence_band: high
cves:
  - id: CVE-2026-66730
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66730
---

CVE-2026-66730 identifies a critical denial-of-service vulnerability affecting facil.io, a C web framework, specifically in versions 0.6.0 through 0.7.6. An unauthenticated remote attacker can exploit this flaw in the multipart body parser by sending a specially crafted `multipart/form-data` request. The core issue lies with a missing progress guard within the parser loop (`http_mime_parse`), which causes it to return zero bytes consumed without setting error or completion flags when encountering a partial closing boundary. This results in the calling loop re-invoking the parser indefinitely on the same buffer, leading to all worker processes consuming 100% CPU and permanently freezing the server, rendering the web service entirely unavailable until a manual restart. This vulnerability poses a significant risk to the availability of applications built with the affected facil.io versions.

## Attack Chain

1. An unauthenticated remote attacker identifies a web server running a vulnerable version of facil.io (0.6.0 to 0.7.6).
2. The attacker crafts a malicious HTTP POST request with the `Content-Type` header set to `multipart/form-data`.
3. The request body is intentionally malformed, including a partial closing boundary for the multipart data.
4. Upon receiving the request, the facil.io server routes it to its multipart body parser (`http_mime_parse`).
5. The parser attempts to process the malformed boundary but, due to a missing progress guard, fails to advance or signal an error.
6. The calling loop repeatedly invokes the parser with the same buffer, causing an infinite loop within the worker process.
7. The affected worker process consumes 100% of its CPU resources and becomes permanently frozen.
8. All available worker processes eventually become similarly frozen, leading to a complete denial of service for the web application, requiring a manual server restart to restore functionality.

## Impact

Successful exploitation of CVE-2026-66730 results in a complete and sustained denial-of-service condition for the affected facil.io web server. All worker processes are permanently locked into an infinite loop, exhausting CPU resources and making the server unresponsive to legitimate requests. This directly translates to significant downtime for any web application or service relying on the vulnerable facil.io instance, necessitating manual intervention and restart, leading to operational disruptions and potential financial losses due to service unavailability. The vulnerability is easily triggered remotely without authentication.

## Recommendation

* Patch CVE-2026-66730 immediately by upgrading facil.io to version 0.7.7 or later to address the vulnerability.
* Monitor web server access logs for repeated or unusual `POST` requests to application endpoints, especially those with `Content-Type: multipart/form-data`.
* Implement rate limiting or web application firewall (WAF) rules to detect and block suspicious `multipart/form-data` requests with malformed boundaries, referencing CVE-2026-66730.
