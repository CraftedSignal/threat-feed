---
brief_id: brief-2026-10-21-camel-proxy-rce
event_id: brief-2026-10-21-camel-proxy-rce
revision: 1
activity_at: "2026-10-21T10:17:47Z"
title: 'Apache Camel: Request forgery vulnerability in camel-platform-http (CVE-2026-85316)'
slug: 2026-10-camel-proxy-rce
description: An unintended proxy mode classification in Apache Camel via prefix matching allows unauthenticated request forgery, potentially exposing internal services to unauthorized access.
date: "2026-10-21T10:17:47Z"
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
tags:
  - camel-platform-http
  - request-forgery
  - ssrf
  - cve-2026-85316
vendors:
  - Apache
products:
  - camel-platform-http (< 4.18.5, 4.19.0 to < 4.22.1)
  - camel-quarkus-platform-http (< 3.40.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unintended proxy mode in camel-platform-http via path prefix matching allows request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-85316
    cvss: 4.8
    epss: 0.00296
    kev_status: "false"
references:
  - https://camel.apache.org/security/CVE-2026-85316.html
  - https://issues.apache.org/jira/browse/CAMEL-24455
  - https://sploitus.com/exploit?id=E3482E50-76C6-5A29-82A5-99AD10DEE104
  - https://sploitus.com/exploit?id=E3482E50-76C6-5A29-82A5-99AD10DEE104&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all services using camel-platform-http for paths starting with "proxy"
      owner: Application Security
      due: 48h
      evidence: Vulnerable behavior is triggered by path names starting with "proxy".
  mitigation_plan:
    - priority: immediate
      action: Upgrade camel-platform-http to 4.22.1 or 4.23.0
      owner: IT Operations
      addresses: CVE-2026-85316
      evidence: Official fix provided by Apache.
---

CVE-2026-85316 is a request forgery vulnerability in the `camel-platform-http` component. The vulnerability is caused by an incorrect implementation of proxy mode identification, where the library evaluates if an endpoint is a proxy by checking if the configured path starts with the string "proxy" instead of requiring an exact match.

Endpoints with paths starting with "proxy" (e.g., "proxyStats", "proxy-health") are incorrectly forced into proxy mode. In this mode, the endpoint acts as a forwarding proxy that uses the client-provided "Host" header to determine its destination. This behavior exposes internal services or resources that the application server can reach.

## Impact

Successful exploitation allows for request forgery, where an attacker can proxy requests through the vulnerable endpoint to reach internal network resources. The severity is mitigated by the need for the application to have existing routes with paths starting with "proxy" that were not intended to serve as proxies.

## Recommendation

- Upgrade `camel-platform-http` to version 4.18.5, 4.22.1, or 4.23.0.
- Upgrade `camel-quarkus-platform-http` to version 3.40.0 or later.
- If upgrading is not immediately possible, identify all `platform-http` endpoints with paths starting with "proxy" that are not intended to act as proxies and rename these paths to avoid the prefix conflict.
