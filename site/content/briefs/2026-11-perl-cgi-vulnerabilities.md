---
brief_id: brief-2026-11-04-perl-cgi-vulnerabilities
event_id: brief-2026-11-04-perl-cgi-vulnerabilities
revision: 1
activity_at: "2026-11-04T02:15:50Z"
title: 'Perl CGI Module: Denial of service and host header injection (CVE-2026-120631, CVE-2026-120632, CVE-2026-120633)'
slug: 2026-11-perl-cgi-vulnerabilities
description: Multiple vulnerabilities in the Perl CGI module library, including versions prior to 5.00, facilitate denial-of-service and CPU exhaustion via regex backtracking and allow host header injection through untrusted X-Forwarded-Host headers.
date: "2026-11-04T02:15:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source corroborated against oss-security advisory
tags:
  - web-application
  - denial-of-service
  - perl
  - cgi
products:
  - CGI (< 5.00)
  - CGI::Cookie (4.67 - 4.99)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CGI versions before 5.00 for Perl allow CPU exhaustion via a backtracking regex on the XForms multipart/related Content-Type
    confidence_band: high
cves:
  - id: CVE-2026-120631
    kev_status: "false"
  - id: CVE-2026-120632
    kev_status: "false"
  - id: CVE-2026-120633
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/508
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Perl CGI module to 5.00 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory notes version 5.00 fixes for multiple CVEs
  hunt_leads:
    - lead: Identify applications using Perl CGI module versions < 5.00
      technique_id: T1190
      data_needed:
        - Software inventory or package manifest logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Advisory impacts CGI versions before 5.00
  mitigation_plan:
    - priority: immediate
      action: Sanitize X-Forwarded-Host header at WAF/Load Balancer
      owner: IT Operations
      addresses: CVE-2026-120633
      evidence: CGI versions before 5.00 trust the client X-Forwarded-Host header
---

The Perl CGI module, versions prior to 5.00, contains multiple security vulnerabilities including potential denial-of-service (DoS) and host header injection. CVE-2026-120631 relates to inefficient regex parsing in CGI::Cookie (v4.67-4.99). CVE-2026-120632 involves CPU exhaustion triggered by a backtracking regex when processing XForms multipart/related Content-Type headers. CVE-2026-120633 involves improper trust of the X-Forwarded-Host header in multiple functions including url and self_url.

## Impact
Applications relying on the Perl CGI module for web request handling are vulnerable to service disruption (DoS/CPU exhaustion) and potentially manipulated request routing or link generation via host header injection.

## Recommendation
- Upgrade the Perl CGI module to version 5.00 or later across all environments.
- Review web application code for reliance on `self_url`, `url`, `virtual_host`, or `virtual_port` functions to assess potential impact from X-Forwarded-Host injection.
- Implement upstream WAF or load balancer rules to sanitize or strip X-Forwarded-Host headers if upgrading is delayed.
- Monitor web server CPU performance for spikes corresponding to multipart requests or cookie processing.
