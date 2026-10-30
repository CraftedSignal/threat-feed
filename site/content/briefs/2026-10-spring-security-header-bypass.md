---
brief_id: brief-2026-10-30-spring-security-header-bypass
event_id: brief-2026-10-30-spring-security-header-bypass
revision: 1
activity_at: "2026-10-30T00:26:18Z"
title: VMware Spring Security Content-Length header suppression (CVE-2026-22732)
slug: 2026-10-spring-security-header-bypass
description: A vulnerability in Spring Security versions < 7.0.4 allows attackers to bypass security header injection by manipulating the Content-Length header, leading to the absence of X-Frame-Options and other security headers.
date: "2026-10-30T00:26:18Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source documentation provides specific vulnerable API patterns for manual review.
cpes:
  - cpe:2.3:a:vmware:spring_security:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - spring-security
  - header-manipulation
vendors:
  - Vmware
products:
  - Spring Security (< 5.7.22, 5.8.24, 6.3.15, 6.4.15, 6.5.9, 7.0.4)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: The vulnerability is triggered when developers use overloaded Servlet methods or WebFlux headers to manually set Content-Length, bypassing the wrapper and suppressing security headers.
    confidence_band: high
cves:
  - id: CVE-2026-22732
    cvss: 9.1
    epss: 0.00489
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MODERNEINC-REWRITE-CVE-2026-22732
  - https://github.com/semgrep/cve-2026-22732-demo
  - https://github.com/jogetworkflow/jw-community/commit/4b3d8479
  - https://github.com/hmcts/idam-web-public/commit/d80b09e0
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MODERNEINC-REWRITE-CVE-2026-22732&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Spring Security to version 6.5.9 or 7.0.4 or higher across all Java applications.
      owner: IT Operations
      due: 72h
      evidence: Spring Security advisory states these versions contain the necessary fixes.
  hunt_leads:
    - lead: Identify applications manually setting Content-Length headers in Servlet responses
      technique_id: T1565
      data_needed:
        - Static analysis of source code for 'setHeader("Content-Length", ...)' or 'setIntHeader("Content-Length", ...)'
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies specific Servlet methods that trigger the bypass.
  mitigation_plan:
    - priority: immediate
      action: Deploy 'BeanPostProcessor' to force eager header writing in environments that cannot be patched immediately.
      owner: Application Security
      addresses: CVE-2026-22732
      evidence: The source provides a code snippet for a 'BeanPostProcessor' that solves the header suppression issue.
---

CVE-2026-22732 is a vulnerability in Spring Security where specific methods for setting the 'Content-Length' header bypass the 'OnCommittedResponseWrapper'. This prevents the wrapper from triggering 'onResponseCommitted()', causing the framework to fail to inject essential security headers such as 'X-Frame-Options', 'X-Content-Type-Options', and 'Cache-Control'. This vulnerability affects multiple versions of Spring Security. Fixes are available in versions 6.5.9 and 7.0.4; for versions where an upgrade is not possible, a 'BeanPostProcessor' configuration can be applied to force eager header writing.

## Impact

Successful exploitation results in the suppression of critical security headers. This exposes applications to various web-based attacks that rely on the absence of browser-side security policies, such as clickjacking (due to missing 'X-Frame-Options') or MIME-sniffing attacks (due to missing 'X-Content-Type-Options').

## Recommendation

- Upgrade Spring Security to the patched versions: 6.5.9 or 7.0.4.
- If upgrading is not immediately feasible, implement a 'BeanPostProcessor' to set 'shouldWriteHeadersEagerly' to 'true' for 'HeaderWriterFilter' beans.
- Audit existing codebase for manual 'Content-Length' header settings using the 'io.moderne.recipe.cve202622732.FindSpringSecurityHeaderSuppression' recipe provided by Moderne.
