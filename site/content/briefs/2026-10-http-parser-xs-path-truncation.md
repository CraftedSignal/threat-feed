---
brief_id: brief-2026-10-31-http-parser-xs-path-truncation
event_id: brief-2026-10-31-http-parser-xs-path-truncation
revision: 1
activity_at: "2026-10-31T19:51:56Z"
title: 'HTTP::Parser::XS: PATH_INFO truncation via encoded NUL byte (CVE-2026-116130)'
slug: 2026-10-http-parser-xs-path-truncation
description: HTTP::Parser::XS versions before 0.18 for Perl are vulnerable to PATH_INFO truncation when an encoded NUL byte is present in the request path, potentially enabling security bypasses in downstream applications.
date: "2026-10-31T19:51:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:http-parser-xs_project:http-parser-xs:*:*:*:*:*:perl:*:*
products:
  - HTTP::Parser::XS (< 0.18)
cves:
  - id: CVE-2026-116130
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/448
  - https://metacpan.org/dist/HTTP-Parser-XS
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade HTTP::Parser::XS to version 0.18 or later in all Perl environments.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-116130 fixed in version 0.18.
  hunt_leads:
    - lead: Identify web server logs or application audit logs containing encoded NUL bytes in the request URI.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application request tracing
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability involves truncation at an encoded NUL byte during request parsing.
  mitigation_plan:
    - priority: immediate
      action: Upgrade HTTP::Parser::XS to 0.18.
      owner: IT Operations
      addresses: CVE-2026-116130
      evidence: OSS-Security advisory identifying 0.18 as the fixed version.
---

The Perl module HTTP::Parser::XS contains a vulnerability (CVE-2026-116130) where the `parse_http_request` function improperly handles encoded NUL bytes. This flaw causes the `PATH_INFO` variable to truncate at the NUL byte. Web applications that use this module for routing or path-based access control may misinterpret the request path, potentially leading to unauthorized access if security checks are bypassed.

## Impact
Applications relying on HTTP::Parser::XS for path-based authorization may be susceptible to security bypasses. An attacker could craft a request containing an encoded NUL byte (e.g., `%00`) to manipulate how the application perceives the requested resource, potentially accessing restricted paths that would otherwise be blocked by validation logic.

## Recommendation
- Inventory all Perl applications utilizing the `HTTP-Parser-XS` module.
- Upgrade `HTTP::Parser::XS` to version 0.18 or later across all environments.
- Review application logic that performs path-based access control to ensure it does not rely solely on input parsed by vulnerable versions of HTTP::Parser::XS.
