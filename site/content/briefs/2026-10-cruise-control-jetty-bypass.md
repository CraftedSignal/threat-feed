---
brief_id: brief-2026-10-cruise-control-jetty-bypass
event_id: brief-2026-10-cruise-control-jetty-bypass
revision: 1
activity_at: "2026-10-20T13:08:28Z"
title: 'Cruise Control: Authentication Bypass via Jetty ConstraintSecurityHandler (CVE-2026-105949)'
slug: 2026-10-cruise-control-jetty-bypass
description: CVE-2026-105949 is an authentication bypass vulnerability in Cruise Control due to improper security constraint configuration and flawed servlet path routing, allowing unauthenticated access to admin endpoints.
date: "2026-10-20T13:08:28Z"
lastmod: "2026-10-20T14:43:18Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:cruise_control_project:cruise_control:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-105949&utm_source=rss&utm_medium=rss
tags:
  - web-application-vulnerability
  - auth-bypass
  - cve-2026-105949
vendors:
  - Cruise Control
products:
  - Cruise Control
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The application fails to register security constraints correctly and utilizes a flawed servlet routing method, allowing unauthenticated attackers to reach admin endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-105949
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105949
  - https://sploitus.com/exploit?id=CVE-2026-105949&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to port 9090 via NetworkPolicy or host-based firewall.
      owner: IT Operations
      due: 24h
      evidence: Source notes NetworkPolicy as a mitigating factor in AMQ Streams.
  hunt_leads:
    - lead: Analyze web logs for traffic to Cruise Control admin endpoints lacking expected authentication headers.
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 15 admin endpoints are reachable without authentication.
updates:
  - at: "2026-10-20T14:43:18Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-105949&utm_source=rss&utm_medium=rss
---

CVE-2026-105949 is an authentication bypass vulnerability in the Cruise Control service, specifically affecting how it handles Jetty security constraints. The application utilizes a Jetty ConstraintSecurityHandler that registers constraints only on exact path specifications without catch-all wildcards or enabling the setDenyUncoveredHttpMethods(true) configuration. Consequently, the application fails to enforce security policies across all intended endpoints.

The vulnerability is compounded by the servlet routing logic, which uses Path.of(pathInfo).getFileName(). This method strips leading path segments and trailing slashes. By crafting requests (e.g., /kafkacruisecontrol/x/rebalance), an unauthenticated attacker can effectively neutralize path-based authentication checks. This leads to the exposure of 15 sensitive administrative endpoints, including those managing cluster rebalancing operations. While network-level mitigations such as Strimzi operator NetworkPolicy rules may limit exposure in certain deployment scenarios, the vulnerability permits full administrative control over the Cruise Control service if the port is reachable.

## Impact

Successful exploitation allows unauthenticated attackers to invoke 15 administrative endpoints within the Cruise Control service. This impact includes the potential to trigger cluster-wide rebalancing, configuration modifications, or other sensitive operational actions without valid credentials. While organizations utilizing the Strimzi operator in AMQ Streams may benefit from inherent NetworkPolicy restrictions on port 9090, deployments with broader network accessibility are at high risk of unauthorized administrative actions.

## Recommendation

1. Deploy infrastructure-level network access control lists (ACLs) or Kubernetes NetworkPolicies to restrict traffic to the Cruise Control port (9090) to authorized management pods only.
2. Implement application-layer logging to identify requests to administrative endpoints that lack associated authentication headers or tokens.
3. Patch the affected Cruise Control installation immediately once the vendor releases a version addressing the Jetty ConstraintSecurityHandler configuration.
4. Perform an audit of existing security constraints within the Jetty configuration to ensure catch-all patterns and denial of uncovered HTTP methods are explicitly defined.
