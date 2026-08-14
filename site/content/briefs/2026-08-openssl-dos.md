---
title: Remote Denial of Service Vulnerability in OpenSSL
slug: 2026-08-openssl-dos
description: A vulnerability (CVE-2026-14456) in OpenSSL versions 3.5.x, 3.6.x, and 4.0.x allows remote attackers to trigger a denial of service condition.
date: "2026-08-14T14:05:29Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - openssl
vendors:
  - OpenSSL
products:
  - OpenSSL 3.5
  - OpenSSL 3.6
  - OpenSSL 4.0
cves:
  - id: CVE-2026-14456
    cvss: 7.5
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1026/
  - https://openssl-library.org/news/secadv/20260813.txt
  - https://www.cve.org/CVERecord?id=CVE-2026-14456
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory affected systems using identified version ranges
      owner: IT Operations
      due: 48h
      evidence: Source explicitly lists affected version branches
  mitigation_plan:
    - priority: immediate
      action: Monitor for and apply vendor patches immediately upon release
      owner: IT Operations
      addresses: CVE-2026-14456
      evidence: Source identifies vulnerability and indicates patches forthcoming
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding a denial of service (DoS) vulnerability identified in the OpenSSL cryptographic library. The vulnerability, tracked as CVE-2026-14456, impacts OpenSSL versions 3.5.x (prior to 3.5.8), 3.6.x (prior to 3.6.4), and 4.0.x (prior to 4.0.2). The vulnerability allows a remote, unauthenticated attacker to cause the application to crash or become unresponsive, effectively creating a denial of service. As of the time of the advisory, the vendor had not yet released patches for the affected versions. Organizations utilizing OpenSSL for network-facing services or encrypted communications are advised to monitor the official OpenSSL security advisories for the release of updates.

## Impact

Successful exploitation results in a remote denial of service condition. This could lead to the unavailability of critical services that rely on OpenSSL for TLS/SSL termination, such as web servers, VPN concentrators, and application proxies. Impacted sectors include any organization relying on the OpenSSL library across varied operating systems and architectures.

## Recommendation

* Monitor the official OpenSSL security advisory page for the release of patches for CVE-2026-14456.
* Audit software inventories to identify applications or services bundling the vulnerable versions of OpenSSL (3.5.x < 3.5.8, 3.6.x < 3.6.4, 4.0.2 < 4.0.2).
* Where possible, implement network-level access controls to restrict traffic to critical services using OpenSSL to trusted source IP addresses until patches are applied.
