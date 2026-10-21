---
brief_id: brief-2026-10-21-django-rest-framework-dos
event_id: brief-2026-10-21-django-rest-framework-dos
revision: 1
activity_at: "2026-10-21T21:41:30Z"
title: 'Django REST framework: Denial of Service via Accept header parsing (CVE-2026-114138)'
slug: 2026-10-django-rest-framework-dos
description: Django REST framework versions prior to 3.18.2 are susceptible to a Denial of Service attack where specially crafted Accept headers cause CPU-intensive parsing and thread exhaustion.
date: "2026-10-21T21:41:30Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; patch version identified.
cpes:
  - cpe:2.3:a:django-rest-framework:django_rest_framework:*:*:*:*:*:*:*:*
vendors:
  - Django Software Foundation
products:
  - Django REST framework (< 3.18.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.002
    technique_name: Service Exhaustion Flood
    evidence: A remote unauthenticated client can send many distinct media types containing large quoted parameter values with numerous semicolons, causing Django's parameter parser and DRF's repeated parsing structure to consume disproportionate CPU.
    confidence_band: high
cves:
  - id: CVE-2026-114138
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114138
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Django REST framework to version 3.18.2 or later
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 3.18.2.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF or reverse proxy to restrict the length and complexity of the Accept header
      owner: IT Operations
      addresses: CVE-2026-114138
      evidence: Unbounded number and aggregate size of Accept tokens are processed by the framework.
---

Django REST framework versions prior to 3.18.2 contain a vulnerability in the `DefaultContentNegotiation` class, specifically within `get_accept_list` and `select_renderer`. The framework fails to limit the number and aggregate size of media type tokens in the HTTP `Accept` header. An attacker can supply a large number of distinct media types containing complex, quoted parameters and excessive semicolons. This forces the server's parser into a cycle of intensive operations that pin synchronous worker threads, leading to service unavailability.

## Impact

A remote, unauthenticated attacker can cause a Denial of Service by exhausting synchronous worker threads, rendering the API unresponsive until the malicious requests cease.

## Recommendation

* Upgrade Django REST framework to version 3.18.2 or later to include the patch for CVE-2026-114138.
* Implement request-level limits on the size and complexity of HTTP headers at the web server or reverse proxy layer (e.g., nginx, Apache) to mitigate the impact of abnormally large `Accept` headers before they reach the application tier.
