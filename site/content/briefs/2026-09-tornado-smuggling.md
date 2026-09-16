---
title: HTTP Request Smuggling Vulnerability in Tornado
slug: 2026-09-tornado-smuggling
description: 'Tornado versions prior to 6.4.1 are vulnerable to HTTP request smuggling via the improper processing of duplicate ''Transfer-Encoding: chunked'' headers when deployed behind a proxy.'
date: "2026-09-15T17:42:32Z"
lastmod: "2026-09-16T01:44:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tornadoweb:tornado:*:*:*:*:*:*:*:*
tags:
  - web-application
  - http-request-smuggling
  - vulnerability
  - request-smuggling
vendors:
  - Tornado
products:
  - Tornado (< 6.4.1)
  - Tornado (< 6.3.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can exploit this inconsistency when Tornado is deployed behind proxies to perform HTTP request smuggling.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: enabling access control bypass, cache poisoning, or connection desynchronization.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1212
    technique_name: Exploitation for Credential Access
    evidence: Attackers can send crafted HTTP requests with these characters to bypass proxy validation and smuggle requests.
    confidence_band: high
cves:
  - id: CVE-2024-14029
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-14029
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54397
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Tornado to version 6.4.1 or later
      owner: IT Operations
      addresses: CVE-2024-14029
      evidence: Source document indicates upgrade to 6.4.1 is required
updates:
  - at: "2026-09-16T01:44:37Z"
    level: L2
    summary: added coverage for Tornado (< 6.3.3)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2023-54397
---

Tornado versions prior to 6.4.1 contain a vulnerability that allows for HTTP request smuggling. The flaw exists because the library incorrectly processes duplicate 'Transfer-Encoding: chunked' headers. When an application using an affected version of Tornado is deployed behind a front-end proxy, the inconsistency between how the proxy and the back-end (Tornado) interpret the request boundaries can be exploited. 

By sending a specially crafted request containing duplicate headers, an attacker can cause Tornado to treat the request as having no message body while simultaneously interpreting the payload as the start of a subsequent, legitimate request. This desynchronization of the HTTP connection allows an attacker to inject requests into the stream processed by the server. This can lead to serious security consequences, including unauthorized access to internal resources, cache poisoning of front-end servers, or the bypassing of security filters applied by the proxy.

## Impact

Successful exploitation allows for connection desynchronization between a proxy and the back-end Tornado server. This enables attackers to perform unauthorized actions such as accessing restricted endpoints, manipulating cached content to serve malicious data to other users, or completely bypassing access control mechanisms. The scope of impact is dependent on the infrastructure configuration, specifically the combination of the front-end proxy and the Tornado-backed application.

## Recommendation

* Upgrade all instances of Tornado to version 6.4.1 or later to remediate CVE-2024-14029.
* Audit proxy configurations to ensure that incoming requests are normalized and that ambiguous or conflicting 'Transfer-Encoding' headers are sanitized or rejected before being forwarded to the application tier.
* Monitor web logs for non-standard HTTP request patterns, such as multiple 'Transfer-Encoding' headers, which may indicate attempts to probe for request smuggling vulnerabilities.
