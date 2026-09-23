---
title: Multiple Security Vulnerabilities in Moquette MQTT Broker
slug: 2026-09-moquette-broker-vulnerabilities
description: Moquette-broker versions <= 0.18.0 are susceptible to cross-tenant ACL bypass, remote unauthenticated denial-of-service, and cross-session durable storage corruption.
date: "2026-09-23T19:56:44Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:moquette_broker:moquette_broker:*:*:*:*:*:*:*:*
tags:
  - mqtt
  - broker
  - authentication-bypass
  - dos
vendors:
  - moquette-broker
products:
  - moquette-broker (<= 0.18.0)
cves:
  - id: CVE-2026-85724
    cvss: 9.6
references:
  - https://github.com/advisories/GHSA-5f42-97gr-vfhq
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85724
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory all MQTT broker instances to identify versions running 0.18.0 or older.
      owner: IT Operations
      due: 24h
      evidence: Source identifies 0.18.0 and earlier as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade moquette-broker to a secure version post-0.18.0.
      owner: IT Operations
      addresses: CVE-2026-85724
      evidence: Remediation guidance provided in source advisory.
---

Moquette-broker versions 0.18.0 and earlier contain multiple high-severity vulnerabilities resulting from inadequate validation of untrusted MQTT client input. The most critical issue (CVE-2026-85724) allows a remote unauthenticated attacker to bypass pattern-based ACLs by injecting wildcard characters (+, #) into the Client ID or username, leading to cross-tenant unauthorized data access and injection. Additional vulnerabilities include a remote unauthenticated denial-of-service (DoS) condition triggered by malformed MQTT packets such as $share subscriptions, which cause uncaught exceptions in the session event loop. Further issues include an authorization bypass for Will-message publications and a cross-session durable corruption bug stemming from H2 storage file collisions. These flaws present a significant risk in multi-tenant environments, as the broker does not sufficiently isolate sessions or validate input prior to processing.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain cross-tenant read and write access, crash the entire MQTT broker service, publish unauthorized Will-messages, or corrupt cross-session durable data. This affects any deployment utilizing pattern-based ACLs in a multi-tenant configuration, potentially leading to widespread information disclosure and service outages.

## Recommendation

1. Upgrade to a version of Moquette-broker that remediates CVE-2026-85724.
2. Implement strict validation on Client ID and username fields during the MQTT CONNECT phase to reject input containing wildcard characters (+, #).
3. Harden the SessionEventLoop to catch all Throwable exceptions and implement a robust supervision strategy to prevent broker-wide crashes.
4. Enforce authorization checks for Will-message publications consistent with standard PUBLISH operations.
5. Implement resource caps on connections, queues, and interceptor queues to mitigate OOM-based DoS risks.
6. Ensure H2 persistent storage namespaces are appropriately separated to prevent ID collisions.
