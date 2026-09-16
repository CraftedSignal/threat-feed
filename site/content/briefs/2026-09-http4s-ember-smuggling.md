---
title: HTTP Request Smuggling Vulnerability in http4s Ember
slug: 2026-09-http4s-ember-smuggling
description: The http4s Ember HTTP/1.1 parser fails to reject messages containing both 'Transfer-Encoding' and 'Content-Length' headers, enabling CL.TE request smuggling attacks.
date: "2026-09-16T01:05:04Z"
lastmod: "2026-09-16T01:06:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:http4s:http4s_ember_core:*:*:*:*:*:*:*:*
tags:
  - request-smuggling
  - cve-2026-69204
  - http-vulnerability
  - denial-of-service
  - vulnerability
  - http2
  - http4s
  - cve-2026-69202
vendors:
  - http4s
products:
  - http4s-ember-core (<= 0.23.34)
  - http4s-ember-core (1.0.0-M1 - 1.0.0-M46)
  - http4s-ember-core (<= 0.23.36)
  - http4s-ember-core (1.0.0-M1 - 1.0.0-M47)
  - http4s-ember-core (<= 0.23.34, >= 1.0.0-M1 and <= 1.0.0-M46)
  - http4s-ember-core (>= 1.0.0-M1, <= 1.0.0-M46)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit this to perform request smuggling, bypassing authentication filters, performing cross-user request hijacking, or poisoning backend caches.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated peer can make Ember's HTTP/2 read loop hold 16 MiB of a single frame in memory... uncontrolled resource consumption leading to unauthenticated remote denial of service.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: 'Endpoint Denial of Service: Application Layer Denial of Service'
    evidence: A remote, unauthenticated peer can exhaust the heap on any Ember endpoint that has HTTP/2 enabled.
    confidence_band: high
cves:
  - id: CVE-2026-69204
references:
  - https://github.com/advisories/GHSA-8h4c-x2wg-6xp8
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69204
  - https://github.com/advisories/GHSA-gq9p-f254-h286
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88975
  - https://github.com/advisories/GHSA-cp4q-fqw9-4hf6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69218
  - https://github.com/advisories/GHSA-9998-894r-fwvr
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-69205
  - https://github.com/advisories/GHSA-6m4x-pp6q-5jmm
  - https://github.com/http4s/http4s/security/advisories/GHSA-8f3q-3jmv-7prw
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade http4s-ember-core to 0.23.35 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-69204
  mitigation_plan:
    - priority: immediate
      action: Configure upstream intermediaries to reject conflicting Transfer-Encoding and Content-Length headers
      owner: IT Operations
      addresses: CVE-2026-69204
      evidence: RFC 9112 §6.1 compliance
updates:
  - at: "2026-09-16T01:05:29Z"
    level: L1
    summary: added coverage for http4s-ember-core (<= 0.23.36) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-gq9p-f254-h286
  - at: "2026-09-16T01:05:43Z"
    level: L1
    summary: added coverage for http4s-ember-core (<= 0.23.34, >= 1.0.0-M1 and <= 1.0.0-M46)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-cp4q-fqw9-4hf6
  - at: "2026-09-16T01:06:01Z"
    level: L2
    summary: added coverage for http4s-ember-core (<= 0.23.34) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-9998-894r-fwvr
  - at: "2026-09-16T01:06:08Z"
    level: L1
    summary: added coverage for http4s-ember-core (<= 0.23.34) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-6m4x-pp6q-5jmm
---

The http4s Ember HTTP/1.1 parser (CVE-2026-69204) fails to comply with RFC 9112 §6.1, which mandates that servers treat any HTTP/1.1 message containing both 'Transfer-Encoding' and 'Content-Length' headers as a framing error and close the connection. Because Ember accepts both, discrepancies arise when it is deployed behind an intermediary that frames the request based on 'Content-Length' while Ember frames based on 'Transfer-Encoding' (chunked). This desynchronization creates a CL.TE request smuggling condition. Attackers can exploit this to perform request smuggling, bypassing authentication filters, performing cross-user request hijacking, or poisoning backend caches. The vulnerability affects both 'ember-server' (origin) and 'ember-client' (response processing), with the latter vulnerable to desynchronization from a malicious upstream source.

## Attack Chain

1. Attacker crafts a malicious HTTP/1.1 request containing both 'Transfer-Encoding: chunked' and a 'Content-Length' header.
2. Attacker sends the request to the intermediary load balancer or reverse proxy sitting in front of the target Ember server.
3. The intermediary processes the 'Content-Length' header, framing the request body accordingly, and forwards the entire packet to the backend Ember server.
4. The backend Ember server, ignoring the 'Content-Length' header in favor of 'Transfer-Encoding', parses the request as chunked.
5. The Ember server interprets only the first chunk of the request, leaving the remainder of the payload in the socket buffer.
6. The residual data in the socket buffer is interpreted by the Ember server as the prefix of the next legitimate user request sent over the same keep-alive connection.
7. Ember processes the smuggled data as a separate request, achieving unauthorized execution or security bypass.

## Impact

Successful exploitation allows for critical security impacts, including the bypassing of front-end security policies, unauthorized cross-user request hijacking, and HTTP cache poisoning. These impacts are most severe in architectures where Ember handles keep-alive backend connections from an intermediary that does not strictly sanitize request headers.

## Recommendation

- Upgrade http4s-ember-core to a non-vulnerable version as soon as patches become available to address CVE-2026-69204.
- Configure upstream intermediaries to strictly reject HTTP/1.1 requests containing both 'Transfer-Encoding' and 'Content-Length' headers.
- Ensure intermediaries buffer and re-encode request bodies to normalize framing before sending them to the backend server.
- Disable keep-alive connections between the intermediary and the Ember backend if immediate patching is not possible.
- Implement web application firewall (WAF) rules to detect and drop HTTP requests containing duplicate or conflicting framing headers.
