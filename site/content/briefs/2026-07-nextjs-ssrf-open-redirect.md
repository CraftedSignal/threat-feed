---
title: Next.js Server-Side Request Forgery and Open Redirect Vulnerability (CVE-2026-64645)
slug: 2026-07-nextjs-ssrf-open-redirect
description: A vulnerability (CVE-2026-64645) in Next.js allows Server-Side Request Forgery (SSRF) and Open Redirect when `rewrites()` or `redirects()` rules in `next.config.js` use attacker-controlled input to construct external destination hostnames, enabling attackers to manipulate dynamic segments from the path or `has` captures to point the rewrite to an arbitrary hostname, potentially leading to internal network access, information disclosure, or redirection of users to malicious sites, affecting Next.js versions from 12.0.0 up to, but not including, 15.5.21, and versions from 16.0.0 up to, but not including, 16.2.11.
date: "2026-07-22T23:03:56Z"
lastmod: "2026-07-22T23:12:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - open-redirect
  - next.js
  - web-vulnerability
  - cve
vendors:
  - Vercel
products:
  - Next.js 12.x
  - Next.js 13.x
  - Next.js 14.x
  - Next.js 15.x
  - Next.js 16.x
  - Next.js (< 15.5.21)
  - Next.js (< 16.2.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A `rewrites()` or `redirects()` rule that builds its external destination hostname from request-controlled input can be pointed at an arbitrary hostname, regardless of the rule's hostname suffix.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1566
    technique_name: Phishing
    evidence: A `redirects()` rule configured this way is vulnerable to an Open Redirect.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: For a rewrite, Next.js proxies the request to that arbitrary host and serves the response from the application's origin, leading to Server-Side Request forgery.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-p9j2-gv94-2wf4
  - https://github.com/advisories/GHSA-89xv-2m56-2m9x
rules:
  - title: Detects CVE-2026-64645 Exploitation - Next.js SSRF/Open Redirect via crafted dynamic segment
    description: Detects exploitation attempts against CVE-2026-64645 in Next.js where attacker-controlled input used in rewrites or redirects contains URL-forming characters (e.g., '://', '@') indicating an SSRF or Open Redirect attempt. This rule targets suspicious patterns in dynamic segments of URL paths or query parameters.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-64649 Exploitation - SSRF Attempt via Host Header Manipulation
    description: Detects CVE-2026-64649 exploitation by identifying HTTP requests where the Host or X-Forwarded-Host header is manipulated to target internal IP addresses or loopback hosts, indicating a Server-Side Request Forgery attempt.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-07-22T23:12:01Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-64649 Exploitation - SSRF Attempt via Host Header Manipulation'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-89xv-2m56-2m9x
---

A high-severity vulnerability, CVE-2026-64645, has been identified in the Next.js framework, affecting versions from 12.0.0 up to 15.5.20 and from 16.0.0 up to 16.2.10. This flaw allows for Server-Side Request Forgery (SSRF) and Open Redirect when an application's `next.config.js` file contains `rewrites()` or `redirects()` rules that construct external destination hostnames using dynamic segments from request-controlled input. An attacker can craft a malicious HTTP request that injects an arbitrary hostname or URL into these dynamic segments, regardless of any intended hostname suffix configured in the rule. This manipulation causes the Next.js application to either proxy requests to an attacker-specified internal or external host (SSRF), or redirect users to a malicious external site (Open Redirect). The vulnerability poses a significant risk for unauthorized access to internal systems, data exfiltration, or successful phishing campaigns.

## Attack Chain

1. Attacker identifies a Next.js application using vulnerable `rewrites()` or `redirects()` rules that derive external destination hostnames from untrusted user input (e.g., path segments like `/:tenant` or query parameters like `?region=`).
2. The attacker crafts a malicious HTTP request by inserting an arbitrary hostname, IP address, or full URL (e.g., `http://internal-service.com/api` or `192.168.1.1/admin`) into the dynamic segment of the request path or query parameter.
3. The Next.js application, processing the request, substitutes the attacker-controlled input into the `destination` field of the `next.config.js` rewrite or redirect rule without proper sanitization.
4. For a `rewrites()` rule, Next.js then proxies the request to the attacker-specified internal or external host (e.g., `https://attacker-controlled.api.example.com` or `http://internal-service.com/api.api.example.com`), sending the response back to the client. This constitutes a Server-Side Request Forgery (SSRF).
5. For a `redirects()` rule, Next.js generates an HTTP 30x redirect response, pointing the user's browser to the attacker-specified external URL (e.g., `https://attacker.com/phish`). This leads to an Open Redirect.
6. Successful exploitation via SSRF allows the attacker to access internal network resources, bypass firewall rules, or scan internal networks. Successful exploitation via Open Redirect can be used for phishing attacks, credential theft, or malware distribution by redirecting unsuspecting users to malicious websites.

## Impact

If successfully exploited, CVE-2026-64645 can lead to severe consequences, including unauthorized access to an organization's internal network infrastructure. Attackers can leverage Server-Side Request Forgery (SSRF) to scan internal networks, interact with otherwise inaccessible internal services, or bypass network segmentation to exfiltrate sensitive data. In the case of an Open Redirect, users can be redirected to arbitrary malicious websites, facilitating phishing campaigns for credential theft, malware delivery, or other social engineering attacks. The exact number of affected organizations is unknown, but any Next.js application using the vulnerable rewrite/redirect configurations in the specified versions is at risk, across all sectors.

## Recommendation

* Upgrade all affected Next.js instances to patched versions: Next.js 15.5.21 or later, or Next.js 16.2.11 or later to remediate CVE-2026-64645.
* As an immediate workaround for CVE-2026-64645, modify your `next.config.js` to ensure that any `rewrites()` or `redirects()` rules do not construct the hostname of an external destination from untrusted user-controlled input.
* If dynamic subdomains are required, constrain the input value using regular expressions to allow only hostname-safe characters (e.g., `value: '(?<region>[a-z0-9-]+)'`).
* Deploy the provided Sigma rule to your SIEM and monitor for HTTP requests containing URL-forming characters in dynamic path segments or query parameters, as these may indicate attempted exploitation of CVE-2026-64645.
