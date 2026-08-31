---
title: 'CVE-2026-81624: Resource Exhaustion in Undertow WebSocket Implementation'
slug: 2026-08-undertow-dos
description: A vulnerability in the Undertow web server used in JBoss EAP and WildFly allows remote attackers to trigger denial of service through WebSocket resource exhaustion due to unconfigurable limits.
date: "2026-08-31T11:17:38Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:redhat:jboss_enterprise_application_platform:*:*:*:*:*:*:*:*
  - cpe:2.3:a:wildfly:wildfly:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - webserver
  - java
vendors:
  - Red Hat
products:
  - JBoss EAP
  - WildFly
  - Undertow
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This allows a remote attacker to send large amounts of data or maintain connections indefinitely, potentially crashing the server by exhausting its memory or other resources.
    confidence_band: high
cves:
  - id: CVE-2026-81624
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81624
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory JBoss EAP and WildFly instances in the environment.
      owner: IT Operations
      due: 48h
      evidence: Undertow is a flexible performant web server used in JBoss EAP and WildFly.
  mitigation_plan:
    - priority: medium_term
      action: Disable WebSocket endpoints in JBoss EAP/WildFly configurations for non-critical services.
      owner: IT Operations
      addresses: CVE-2026-81624
      evidence: Specifically, certain configuration limits like message buffer sizes and session timeouts cannot be adjusted and default to being unlimited.
---

CVE-2026-81624 is a resource exhaustion vulnerability affecting the Undertow web server, a core component of JBoss EAP and WildFly. The flaw arises because the implementation fails to enforce configurable limits on WebSocket message buffer sizes and session timeouts, defaulting these settings to be effectively unlimited. A remote, unauthenticated attacker can exploit this by opening and maintaining an excessive number of WebSocket connections or by flooding the server with large data payloads. By keeping these connections alive indefinitely or consuming available memory through buffer saturation, an attacker can trigger a denial of service (DoS), rendering the server unresponsive to legitimate requests. Given its role in enterprise application servers, this vulnerability represents a significant risk for organizations relying on Java-based middleware to handle high-concurrency traffic.

## Impact

Successful exploitation results in denial of service, potentially causing system crashes and service unavailability for applications hosted on JBoss EAP or WildFly. This impacts availability of web-based services and administrative interfaces, forcing a restart of the application server to restore functionality.

## Recommendation

Prioritize auditing your infrastructure to identify JBoss EAP and WildFly instances exposing WebSocket endpoints to the internet. Since specific patch or configuration guidance is pending, monitor application server logs for abnormal patterns of WebSocket connection persistence or high memory consumption. Disable WebSocket functionality for services where it is not business-critical to minimize the attack surface.
