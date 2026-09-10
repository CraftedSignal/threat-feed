---
title: Multiple Vulnerabilities in Netty Framework
slug: 2026-09-netty-vulnerabilities
description: Multiple vulnerabilities in the Netty framework allow a remote, unauthenticated attacker to trigger denial-of-service, bypass security, perform request smuggling, and manipulate or disclose data.
date: "2026-09-10T18:53:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
  - cpe:2.3:a:miraheze:createwiki:*:*:*:*:*:*:*:*
  - cpe:2.3:a:miraheze:wikidiscover:*:*:*:*:*:*:*:*
cves:
  - id: CVE-2024-47781
    cvss: 6.1
    epss: 0.00308
  - id: CVE-2024-47782
    cvss: 7.6
    epss: 0.00319
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3291
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47781
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47782
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications utilizing Netty as a library component.
      owner: Application Security
      due: 48h
  mitigation_plan:
    - priority: immediate
      action: Update Netty dependencies to the latest patched versions as identified in CVE-2024-47781 and CVE-2024-47782.
      owner: IT Operations
---

The Netty framework is affected by multiple vulnerabilities (CVE-2024-47781, CVE-2024-47782) that expose applications to a variety of remote attacks. An unauthenticated attacker can leverage these flaws to induce Denial-of-Service (DoS) conditions, effectively impacting the availability of services built on the framework. Furthermore, the vulnerabilities enable security control bypasses, which may permit unauthorized access or actions that the application logic intended to restrict. 

The presence of request and response smuggling vulnerabilities is particularly critical, as these allow attackers to interfere with the way proxies and backend servers process HTTP traffic, potentially leading to unauthorized data disclosure or the manipulation of requests between legitimate users and the server. Defenders should identify applications utilizing the vulnerable Netty versions and prioritize patching or updating to the manufacturer's recommended secure version.

## Impact

Successful exploitation of these vulnerabilities can lead to service disruption, unauthorized data exposure, and manipulation of HTTP communications. Depending on the architecture of the host application, these flaws may permit a remote attacker to gain unauthorized access to sensitive internal requests or bypass authentication mechanisms that rely on proper request handling.

## Recommendation

Prioritize inventory mapping of all services utilizing Netty as a dependency. Review internal vulnerability management systems for applications linking against Netty versions identified in CVE-2024-47781 and CVE-2024-47782. Apply patches provided by the project maintainers immediately. Monitor web server and reverse proxy logs for anomalous HTTP request patterns that deviate from standard RFC compliance, which may indicate attempted request smuggling.
