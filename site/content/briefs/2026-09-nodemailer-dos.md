---
title: Nodemailer Addressparser Denial of Service via CVE-2026-90776
slug: 2026-09-nodemailer-dos
description: Nodemailer versions 9.1.0 through 10.0.4 are vulnerable to a denial of service attack where malicious email headers trigger quadratic time complexity in the addressparser component, exhausting CPU resources.
date: "2026-09-13T13:25:34Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:nodemailer:nodemailer:9.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:nodemailer:nodemailer:10.0.4:*:*:*:*:*:*:*
vendors:
  - Nodemailer
products:
  - Nodemailer (9.1.0-10.0.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can craft malicious email headers with comment-separated atoms to consume excessive CPU and block the Node.js event loop for several seconds, causing denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-90776
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90776
action_plan:
  priority: elevated
  owners:
    - Engineering
    - Application Security
  immediate_actions:
    - action: Upgrade Nodemailer to version 10.0.5 or later to resolve CVE-2026-90776
      owner: Engineering
      due: 48h
      evidence: Upgrade required to address quadratic time complexity vulnerability in addressparser
  mitigation_plan:
    - priority: immediate
      action: Implement length limits on user-supplied email header input
      owner: Application Security
      addresses: CVE-2026-90776
      evidence: Source describes exploitation via malicious headers
---

Nodemailer versions 9.1.0 through 10.0.4 contain a vulnerability in the addressparser component that results in a quadratic time complexity condition when parsing email addresses containing RFC 5322 comments. An attacker can craft and submit specific email headers featuring deeply nested or complex comment-separated atoms. When the application attempts to process these headers, the addressparser library consumes excessive CPU cycles, effectively blocking the Node.js event loop for an extended period. Because Node.js operates on a single-threaded event loop, this resource exhaustion prevents the application from processing any other incoming requests, leading to a denial of service. This vulnerability is particularly critical for high-traffic mail servers or applications that rely on Nodemailer to ingest user-supplied email headers.

## Impact

Successful exploitation results in a persistent denial of service condition for the targeted Node.js application. By sending a single crafted request or a low-volume stream of crafted headers, an attacker can cause legitimate application traffic to fail, potentially disrupting business-critical communication systems or automated email processing workflows. No data exfiltration is associated with this vulnerability, but the loss of availability can significantly impact services relying on Nodemailer.

## Recommendation

Prioritized, concrete actions for development and security engineering teams:
- Upgrade Nodemailer to version 10.0.5 or later, which contains the fix for the quadratic parsing issue.
- Audit all applications utilizing Nodemailer to determine if user-controlled input is passed directly to email header fields processed by the library.
- Implement input validation and length limits on email header fields to prevent processing of excessively large or malformed strings if upgrading is not immediately possible.
- Monitor application logs for high CPU usage spikes or event loop blockages occurring concurrently with incoming email requests to identify potential exploitation attempts.
