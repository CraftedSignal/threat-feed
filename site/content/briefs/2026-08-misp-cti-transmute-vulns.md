---
title: Vulnerabilities in MISP cti-transmute
slug: 2026-08-misp-cti-transmute-vulns
description: The MISP project has patched multiple security vulnerabilities in the cti-transmute tool, including arbitrary file/network access and improper authorization controls for user management.
date: "2026-08-04T19:43:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - cti-transmute
  - misp
  - patch-management
vendors:
  - MISP
products:
  - cti-transmute (1.4.0)
references:
  - https://cyber.gc.ca/en/alerts-advisories/misp-security-advisory-av26-775
  - https://github.com/MISP/cti-transmute/commit/20f35307bcb706c8dd8ca3884a88fb36b05b5244
  - https://github.com/MISP/cti-transmute/commit/321892d26b82c8a5af1e210ee30735abb109fac2
  - https://github.com/MISP/cti-transmute/commit/4f0d051ec5f1d45894c26987d409411728b2d82c
iocs:
  - type: url
    value: https://github.com/MISP/cti-transmute/commit/20f35307bcb706c8dd8ca3884a88fb36b05b5244
  - type: url
    value: https://github.com/MISP/cti-transmute/commit/321892d26b82c8a5af1e210ee30735abb109fac2
  - type: url
    value: https://github.com/MISP/cti-transmute/commit/4f0d051ec5f1d45894c26987d409411728b2d82c
ioc_counts:
  url: 3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade cti-transmute installations to version > 1.4.0.
      owner: IT Operations
      due: 72h
      evidence: MISP security advisory AV26-775
---

The MISP project has issued a security advisory for the cti-transmute utility affecting all versions up to and including 1.4.0. The updates address several security weaknesses identified in the tool's handling of web requests and administrative actions. Specifically, the patches block unauthorized file and network fetches triggered during PDF evaluation, enforce stricter limits on activity-timeline day ranges to mitigate resource exhaustion, and mandate HTTP POST methods for user deletion to prevent unauthorized administrative actions via cross-site request forgery (CSRF) or simple GET requests. Users are advised to upgrade to the latest version to prevent potential exploitation of these flaws.

## Impact

Successful exploitation of these vulnerabilities could lead to unauthorized access to sensitive files, unintended network connections originating from the application server, and unauthorized administrative actions such as the deletion of application users. Organizations utilizing cti-transmute for threat intelligence processing or reporting workflows are potentially at risk if the application is accessible to untrusted users or processes malicious input.

## Recommendation

* Update cti-transmute to the latest available version beyond 1.4.0 to ensure all security patches are applied.
* Audit web server and application logs for unusual GET requests to endpoints associated with user management, as these may indicate attempts to leverage the user deletion flaw.
* Review network egress logs for unexpected connections originating from the host running cti-transmute, which may indicate exploited file or network fetch vulnerabilities.
* Implement strict access controls for the cti-transmute interface to ensure only authorized personnel can trigger evaluation functions.
