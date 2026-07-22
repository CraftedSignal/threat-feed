---
title: 'Next.js: Denial of Service in App Router using Server Actions'
slug: 2026-07-nextjs-dos
description: A high-severity denial-of-service vulnerability (CVE-2026-64641) in Next.js applications utilizing the App Router with Server Actions allows an unauthenticated attacker to cause excessive CPU usage, leading to a complete service outage.
date: "2026-07-22T22:59:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - web-application
  - javascript
  - nodejs
vendors:
  - Vercel
products:
  - Next.js (>= 13.0.0, < 15.5.21)
  - Next.js (>= 16.0.0, < 16.2.11)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Crafted requests targeting Next.js applications using App Router with at least one Server Action can lead to excessive CPU usage blocking processing of further requests in the same process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-m99w-x7hq-7vfj
  - https://github.com/vercel/next.js/issues/96013
  - https://github.com/vercel/next.js/commit/0196285
  - https://github.com/vercel/next.js/releases/tag/v15.5.21
  - https://github.com/vercel/next.js/releases/tag/v16.2.11
---

A high-severity denial-of-service vulnerability, identified as CVE-2026-64641, affects Next.js applications that are configured to use the App Router alongside at least one Server Action. This flaw allows an unauthenticated remote attacker to send specially crafted HTTP requests to the vulnerable application. Upon receiving such a request, the Next.js process can enter a state of excessive CPU utilization, thereby blocking the processing of all further legitimate requests. This sustained resource exhaustion leads to a complete unavailability of the web service for legitimate users. The vulnerability affects Next.js versions greater than or equal to 13.0.0 and less than 15.5.21, as well as versions greater than or equal to 16.0.0 and less than 16.2.11. Applications not employing the App Router or Server Actions are not susceptible. This vulnerability poses a significant risk to the availability of critical web applications built with Next.js, making immediate patching crucial for maintaining service uptime.

## Attack Chain

1. An unauthenticated attacker sends a specially crafted HTTP request to a vulnerable Next.js application endpoint.
2. The crafted request specifically targets an application configured with the App Router and at least one Server Action.
3. Processing the malicious request triggers an uncontrolled internal operation, causing the Next.js application process to consume excessive CPU resources.
4. The sustained, high CPU utilization overwhelms the application, preventing it from handling legitimate incoming requests.
5. The Next.js application becomes unresponsive, resulting in a denial of service for all users.

## Impact

Successful exploitation of CVE-2026-64641 leads to a complete denial of service for affected Next.js applications. Attackers can trigger excessive CPU usage in the application process, which in turn blocks the processing of all further requests. This effectively renders the web application inaccessible to legitimate users, disrupting business operations and potentially causing significant financial losses due to service downtime. There is no observed data on the number of victims or specific sectors targeted, but any organization using vulnerable Next.js versions with the App Router and Server Actions is at risk.

## Recommendation

* Patch CVE-2026-64641 immediately by upgrading Next.js to version 15.5.21 or later, or 16.2.11 or later, as referenced in the affected_products section.
* Monitor CPU utilization on servers hosting Next.js applications, especially those using App Router and Server Actions, for anomalous spikes indicative of a DoS attack.
* Monitor web server access logs for unusual patterns or high request rates directed towards Next.js App Router endpoints that utilize Server Actions.
