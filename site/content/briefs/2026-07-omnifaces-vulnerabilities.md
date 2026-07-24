---
title: Multiple High-Severity Vulnerabilities in OmniFaces Library
slug: 2026-07-omnifaces-vulnerabilities
description: Multiple vulnerabilities in OmniFaces versions prior to 1.14.3, 2.7.33, 3.14.23, 4.7.12, and 5.4.2 allow attackers to exploit forged combined-resource IDs leading to server-side request forgery (SSRF)-like behavior or information disclosure, achieve client-side arbitrary code execution via cross-site scripting (XSS) in `o:hashParam`, bypass session authentication for push channels resulting in unauthorized message interception, and cause denial-of-service (DoS) via unbounded caches.
date: "2026-07-24T22:40:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - ssrf
  - xss
  - dos
  - java
  - omnifaces
  - information-disclosure
  - session-hijacking
vendors:
  - OmniFaces
products:
  - 'omnifaces (vulnerable: < 1.14.3)'
  - 'omnifaces (vulnerable: >= 2.0.0, < 2.7.33)'
  - 'omnifaces (vulnerable: >= 3.0.0, < 3.14.23)'
  - 'omnifaces (vulnerable: >= 4.0.0, < 4.7.12)'
  - 'omnifaces (vulnerable: >= 5.0.0, < 5.4.2)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attacker crafts a path-derived ID without an authenticity check, inflates it without an output limit, converts it to attacker-selected resource identifiers... A URL-fragment value containing a single-quote JavaScript payload was stored by `o:hashParam` and later written unescaped into the Ajax callback script.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: ""
    evidence: A fresh WebSocket client with no HTTP cookie connected using a victim's session-scoped channel ID and received the victim's subsequent push.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1071
    technique_name: ""
    evidence: A forged `omnifaces.graphic` inner resource plus a canary `Host` header caused an outbound GET to that host.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A forged inner `.xhtml` resource bypassed the excluded-resource boundary and returned its raw content.
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1059
    technique_name: ""
    evidence: A URL-fragment value containing a single-quote JavaScript payload was stored by `o:hashParam` and later written unescaped into the Ajax callback script. On the follow-up Ajax render, real Chrome executed the canary `window.__omniXss=1337`.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: With the documented optional source-map handler above a synthetic resource handler, 40 unique missing combined-resource requests grew the process-wide source-map cache from 13 to 92 entries. It has no size or eviction bound... Current code sets every accepted session's maximum idle timeout to zero, retains sessions in an unbounded per-channel queue, and walks the full queue on each push.
    confidence_band: high
cves:
  - id: CVE-2026-41883
    cvss: 8.1
    epss: 0.00382
references:
  - https://github.com/advisories/GHSA-fp43-vj7g-pg92
---

The OmniFaces project, a utility library for JavaServer Faces (JSF), published an advisory on July 24, 2026, detailing multiple high-severity vulnerabilities affecting various versions (specifically, prior to 1.14.3, 2.7.33, 3.14.23, 4.7.12, and 5.4.2). These issues include the exploitation of forged combined-resource IDs to bypass security boundaries, potentially leading to information disclosure of internal application resources or enabling server-side request forgery (SSRF)-like behavior through outbound connections. An XSS vulnerability allows client-side script execution due to improper escaping of JavaScript payloads from `o:hashParam`. Furthermore, session-scoped push channels are vulnerable to replay attacks, allowing unauthorized access to a victim's push messages. The presence of unbounded static caches and per-channel queues also introduces denial-of-service (DoS) risks through resource exhaustion, posing significant threats to data confidentiality, integrity, and availability. These issues are distinct from a prior CVE-2026-41883 fix, originating from unsigned combined IDs, missing decode/cache bounds, and improper input handling.

## Attack Chain

1. Attacker crafts an HTTP request containing a forged `CombinedResourceInfo` ID or a URL with an unescaped JavaScript payload intended for `o:hashParam`.
2. The OmniFaces application processes the request, either accepting the forged ID due to missing authenticity checks or storing the unescaped JavaScript payload.
3. For forged IDs, the application performs server-side fetches of internal resources (bypassing exclusion rules) or initiates outbound connections to attacker-specified hosts (SSRF-like behavior), potentially disclosing internal information.
4. For the `o:hashParam` vulnerability, a victim's browser executes the unescaped JavaScript payload during a subsequent Ajax render, leading to client-side attacks.
5. An attacker obtains a legitimate session-scoped push channel ID from a victim and reuses it to subscribe to the victim's push notifications, gaining unauthorized access to sensitive real-time data.
6. Through repeated exploitation of unbounded caches (e.g., combined-resource IDs, source-map cache) or per-channel queues, the attacker causes resource exhaustion on the server, leading to application instability or denial of service for legitimate users.

## Impact

The vulnerabilities allow for various severe impacts. Successful exploitation of forged combined-resource IDs can lead to sensitive information disclosure from internal application resources or enable server-side request forgery (SSRF)-like attacks, potentially allowing attackers to scan internal networks or interact with internal services. The cross-site scripting (XSS) vulnerability can result in client-side arbitrary code execution, enabling session hijacking, credential theft, or defacement of web pages for affected users. The session/view push-channel replay vulnerability permits unauthorized interception of real-time push messages intended for specific users, compromising data confidentiality. Additionally, multiple unbounded caches and queues create denial-of-service (DoS) opportunities, allowing attackers to exhaust server memory, CPU, or network resources, leading to application crashes or complete service unavailability.

## Recommendation

* Upgrade OmniFaces to a patched version (1.14.3, 2.7.33, 3.14.23, 4.7.12, or 5.4.2) immediately to mitigate all described vulnerabilities.
* Monitor web server access logs for unusual request patterns, particularly those involving `CombinedResourceInfo` paths or `o:hashParam` with unusual or encoded characters.
* Implement outbound network traffic monitoring to detect unexpected connections initiated by the application server, which could indicate SSRF-like activity from forged combined-resource IDs.
* Review application logs for signs of resource exhaustion, such as excessive memory usage or frequent garbage collection events, potentially indicating denial-of-service attempts related to unbounded caches or queues.
