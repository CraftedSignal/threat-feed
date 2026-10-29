---
brief_id: brief-2026-10-29-happy-dom-ssrf
event_id: brief-2026-10-29-happy-dom-ssrf
revision: 1
activity_at: "2026-10-29T06:12:37Z"
title: 'Happy DOM: Server-side request forgery via default HTML parsing (CVE-2026-118660)'
slug: 2026-10-happy-dom-ssrf
description: Happy DOM versions up to 20.14.6 are vulnerable to SSRF because they allow default external resource fetching for iframe and link stylesheet elements during untrusted HTML parsing.
date: "2026-10-29T06:12:37Z"
type: advisory
types:
  - advisory
severities:
  - high
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
  - cpe:2.3:a:happy-dom:happy-dom:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - library-vulnerability
  - web-application-security
products:
  - happy-dom (<= 20.14.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker providing untrusted HTML to an application using happy-dom for server-side parsing can force the application to perform unauthorized HTTP requests.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: An attacker can trigger Server-Side Request Forgery by embedding these elements... probe internal services and ports.
    confidence_band: high
cves:
  - id: CVE-2026-118660
    cvss: 8.6
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-c8p4-j97h-3vg8
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-118660
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: Review all instances of Happy DOM implementation in server-side code to determine if untrusted HTML is processed.
      owner: Development
      due: 48h
      evidence: Source states happy-dom is used for server-side parsing of untrusted HTML.
  hunt_leads:
    - lead: Search application logs for outbound HTTP GET requests originating from backend servers to cloud metadata endpoints (e.g., 169.254.169.254) or unexpected internal IP ranges.
      technique_id: T1046
      data_needed:
        - Network flow logs or egress proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Cloud metadata attack scenario allows fetching data from 169.254.169.254.
  mitigation_plan:
    - priority: immediate
      action: Modify Happy DOM window configuration to set disableIframePageLoading to true and disableCSSFileLoading to true.
      owner: Development
      addresses: CVE-2026-118660
      evidence: Suggested fix provided in advisory.
---

Happy DOM versions through 20.14.6 perform real server-side HTTP requests when parsing HTML content containing `<iframe>` or `<link rel="stylesheet">` elements. This occurs because the default configurations `disableIframePageLoading` and `disableCSSFileLoading` are both set to `false`. When an application uses this library to parse untrusted user-provided HTML, an attacker can trigger unauthorized HTTP requests to internal resources or cloud metadata services.

## Impact

Successful exploitation allows attackers to perform internal network reconnaissance, probe private services, or exfiltrate cloud metadata (such as IAM credentials from `169.254.169.254`).

## Recommendation

* Update any application code using Happy DOM to explicitly disable external resource loading in the configuration settings.
* Set `disableIframePageLoading: true` and `disableCSSFileLoading: true` in your `Window` initialization code.
* Implement server-side URL validation to deny requests to RFC1918 private IP ranges and cloud metadata service endpoints (e.g., `169.254.169.254`).
