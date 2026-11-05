---
brief_id: brief-2026-11-05-apache-juneau-credential-exposure
event_id: brief-2026-11-05-apache-juneau-credential-exposure
revision: 1
activity_at: "2026-11-05T16:32:24Z"
title: 'Apache Juneau: Credential exposure via RestClient HTTP redirects (CVE-2026-73116)'
slug: 2026-11-apache-juneau-credential-exposure
description: Apache Juneau RestClient prior to version 9.2.1 contains a vulnerability where sensitive header information is forwarded across origins during HTTP redirects, enabling unauthorized credential interception.
date: "2026-11-05T16:32:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Patch released by vendor; validation pending environment-specific testing
cpes:
  - cpe:2.3:a:apache:juneau:*:*:*:*:*:*:*:*
vendors:
  - Apache
products:
  - Juneau (<= 9.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The Apache Juneau RestClient followed HTTP redirects while keeping credential headers from the original request, so a server that redirected the client to a different host or port, or from HTTPS to HTTP, could receive headers such as Authorization, Cookie, Proxy-Authorization and X-API-Key.
    confidence_band: high
cves:
  - id: CVE-2026-73116
    kev_status: "false"
references:
  - https://lists.apache.org/thread.html/j05q7vw08j48o96tdlzcsd4sozx1lyl6
  - https://sploitus.com/exploit?id=CVE-2026-73116
  - https://sploitus.com/exploit?id=CVE-2026-73116&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory applications utilizing Apache Juneau RestClient and upgrade to 9.2.1.
      owner: IT Operations
      due: 48h
      evidence: Users are recommended to upgrade to version 9.2.1, which fixes the issue.
  hunt_leads:
    - lead: Identify outbound HTTP traffic from servers using Apache Juneau where HTTP status codes indicate 301/302 redirects to different hostnames.
      technique_id: T1592
      data_needed:
        - Proxy/WAF logs
        - Application egress logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The RestClient followed HTTP redirects while keeping credential headers from the original request.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Juneau to 9.2.1 or implement custom HttpClient logic to strip sensitive headers on cross-origin redirects.
      owner: IT Operations
      addresses: CVE-2026-73116
      evidence: The fix applies to HTTP clients created by the RestClient builder; applications that supply their own HttpClient must disable automatic redirects or strip credential headers on cross-origin redirects themselves.
---

Apache Juneau RestClient (through version 9.2.0) incorrectly maintains sensitive credential headers (such as Authorization, Cookie, Proxy-Authorization, and X-API-Key) when following HTTP redirects. If a client is redirected by a server to a different host, port, or from HTTPS to HTTP, the RestClient may automatically leak these headers to the destination. 

## Impact
Successful exploitation allows a malicious or compromised server to intercept sensitive authentication tokens or cookies sent by the RestClient, facilitating account takeover or unauthorized access to backend services.

## Recommendation
- Upgrade Apache Juneau to version 9.2.1 or later.
- If using a custom HttpClient, ensure that automatic redirects are disabled or that credential headers are explicitly stripped during cross-origin redirect events.
