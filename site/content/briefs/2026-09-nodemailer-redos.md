---
title: CVE-2026-100700 Denial of Service in Nodemailer
slug: 2026-09-nodemailer-redos
description: Nodemailer versions before 10.0.6 are vulnerable to a Regular Expression Denial of Service (ReDoS) in the addressparser component, allowing attackers to block the Node.js event loop via crafted email headers.
date: "2026-09-26T15:12:59Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:nodemailer:nodemailer:*:*:*:*:*:*:*:*
vendors:
  - Nodemailer
products:
  - nodemailer (< 10.0.6)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can supply crafted email header values with long whitespace-free runs to block the Node.js event loop for tens of seconds, causing service unavailability.
    confidence_band: high
cves:
  - id: CVE-2026-100700
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100700
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade nodemailer to version 10.0.6 or later
      owner: IT Operations
      addresses: CVE-2026-100700
      evidence: Nodemailer before 10.0.6 contains a denial of service vulnerability
---

Nodemailer versions prior to 10.0.6 contain a Regular Expression Denial of Service (ReDoS) vulnerability in the addressparser component. The flaw exists within a free-text fallback regular expression pattern that exhibits quadratic backtracking behavior when processing specific input strings. By submitting crafted email header values containing long sequences of non-whitespace characters, an attacker can force the regex engine to enter a state of extreme computational complexity. Because Node.js operates on a single-threaded event loop, this excessive processing blocks the event loop for tens of seconds, rendering the affected application unresponsive and causing service unavailability. This vulnerability is particularly critical for applications that process user-supplied email data or headers without validation.

## Impact

Successful exploitation results in a Denial of Service (DoS) condition, forcing the Node.js application to become unavailable by blocking its primary event loop. This can impact any service relying on Nodemailer for email processing or header parsing, potentially leading to widespread outages in applications that process external email inputs.

## Recommendation

- Upgrade the nodemailer package to version 10.0.6 or later immediately to incorporate the fixed addressparser regex logic.
- Audit applications utilizing Nodemailer to identify input vectors where user-controlled email header data is passed to the library.
- Implement length constraints on all input strings that are subsequently passed to email header parsing functions to mitigate the risk of triggering catastrophic backtracking.
