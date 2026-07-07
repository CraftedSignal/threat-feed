---
title: '@conform-to/dom Vulnerable to CPU Exhaustion via Crafted Form Submissions'
slug: 2026-07-cpu-exhaustion-conform-dom
description: A CPU exhaustion vulnerability (CVE-2026-49250) exists in Conform's `parseSubmission` API when parsing `FormData` or `URLSearchParams` with many unique field names, allowing an attacker to craft a submission that causes excessive synchronous CPU work and potential denial of service by repeatedly scanning submitted entries.
date: "2026-07-03T11:44:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - web-application
  - denial-of-service
  - cpu-exhaustion
  - npm
products:
  - npm/@conform-to/dom (< 1.19.4)
references:
  - https://github.com/advisories/GHSA-525m-7f82-2mf7
---

A high-severity CPU exhaustion vulnerability, identified as CVE-2026-49250, has been discovered in the `@conform-to/dom` npm package, specifically within its `parseSubmission` future API. This vulnerability affects versions greater than or equal to 1.8.0 and less than 1.19.4. The issue arises when the API processes `FormData` or `URLSearchParams` submissions containing a large number of unique field names. An attacker can exploit this by sending a specially crafted submission, causing the parser to repeatedly scan submitted entries during value lookups. This inefficient processing leads to excessive synchronous CPU utilization on the server, ultimately resulting in CPU exhaustion and a denial of service (DoS) condition for the affected application. This vulnerability is critical for applications that accept untrusted or arbitrary form submissions.

## Attack Chain

1. An attacker identifies a web application using `@conform-to/dom`'s `parseSubmission` API for form processing.
2. The attacker crafts a malicious HTTP POST request containing `FormData` or `URLSearchParams`.
3. The crafted request includes a significantly large number of unique field names within its body.
4. The victim application receives the request and invokes `parseSubmission` to process the incoming form data.
5. During the parsing process, `parseSubmission` attempts to look up values by field name.
6. Due to the high volume of unique field names, the parser repeatedly iterates through the entire list of submitted entries for each lookup.
7. This repeated scanning consumes excessive synchronous CPU cycles on the server hosting the application.
8. The prolonged CPU exhaustion leads to a denial of service (DoS) for the application, making it unresponsive or unavailable to legitimate users.

## Impact

The primary impact of CVE-2026-49250 is a denial of service (DoS) condition for applications utilizing the vulnerable `@conform-to/dom` package. If successfully exploited, an attacker can render the web application unresponsive or completely unavailable by causing its CPU resources to be fully consumed. This can lead to significant operational disruption, financial losses due to service downtime, and reputational damage for affected organizations. Any application that processes untrusted form submissions using vulnerable versions of `@conform-to/dom` is at risk, irrespective of the industry sector.

## Recommendation

*   Upgrade the `npm/@conform-to/dom` package to version 1.19.4 or higher immediately to patch CVE-2026-49250.
*   Implement request parsing limits *before* passing data to the Conform `parseSubmission` API. For multipart requests, utilize `@remix-run/form-data-parser` with options such as `maxParts`, `maxTotalSize`, `maxFileSize`, `maxFiles`, and `maxHeaderSize` to mitigate CPU exhaustion.
