---
title: Critical Authentication Bypass in Spikster API
slug: 2026-07-spikster-auth-bypass
description: A missing authentication vulnerability in Spikster allows unauthenticated remote attackers to access approximately 50 API endpoints, leading to full system compromise.
date: "2026-07-30T21:31:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - cve-2026-67594
  - rce
vendors:
  - Spikster
products:
  - Spikster (<= e1cdf8c)
cves:
  - id: CVE-2026-67594
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67594
---

Spikster, up to and including commit e1cdf8c, contains a critical security vulnerability (CVE-2026-67594) characterized by missing authentication on its API routes. The application includes a 'CipiAuth' middleware component intended to secure API access; however, this middleware is correctly registered within the application framework but never actually applied to any specific API route definitions. 

As a result, an unauthenticated remote attacker can interact with approximately 50 protected API endpoints. These endpoints provide extensive control over the managed environment, including the ability to provision new servers, reset administrative root passwords, perform arbitrary file read and write operations on the underlying host, and create new database users. Given the high-privileged nature of these actions, successful exploitation grants the attacker full control over the application and the host server, making this an extremely high-impact vulnerability for any infrastructure relying on Spikster for management.

## Impact

The vulnerability allows unauthenticated access to system management functions, which can lead to complete server takeover, unauthorized data access, persistence through new database users, and arbitrary code execution via file write operations. This affects any deployment running Spikster versions up to commit e1cdf8c.

## Recommendation

* Patch Spikster immediately to a version beyond commit e1cdf8c where the CipiAuth middleware is correctly applied to all API route groups.
* Audit access logs for any unauthorized POST, PUT, or DELETE requests directed to administrative API endpoints that do not originate from authenticated sessions.
* Restrict network access to the Spikster API interface to trusted management IP addresses only via a Web Application Firewall (WAF) or network ACLs.
