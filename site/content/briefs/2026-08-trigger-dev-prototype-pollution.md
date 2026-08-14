---
title: Prototype Pollution in Trigger.dev Run Metadata API
slug: 2026-08-trigger-dev-prototype-pollution
description: An unauthenticated-accessible prototype pollution vulnerability in the Trigger.dev metadata API allows low-privileged attackers to corrupt the global object, leading to cross-tenant denial of service and process crashes via CVE-2026-73654.
date: "2026-08-14T02:03:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - rce
  - vulnerability
  - webserver
vendors:
  - Trigger.dev
products:
  - trigger.dev (3.3.8 - 4.5.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: A single request from any holder of a normal environment API key contaminates Object.prototype in the shared webapp process.
    confidence_band: high
cves:
  - id: CVE-2026-73654
    cvss: 8.5
references:
  - https://github.com/advisories/GHSA-p28v-f755-9qrg
  - CVE-2026-73654
rules:
  - title: Detect CVE-2026-73654 Exploitation Attempt
    description: Detects PUT requests to the run metadata endpoint containing potential prototype pollution payloads in the operation key.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1565.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Trigger.dev instances to 4.5.6 or higher
      owner: IT Operations
      due: 24h
      evidence: Advisory states fixed in 4.5.6
  hunt_leads:
    - lead: Search logs for PUT requests to /api/v1/runs/*/metadata containing __proto__, constructor, or prototype
      technique_id: T1565.003
      data_needed:
        - Webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC demonstrates these keys trigger the vulnerability
---

Trigger.dev versions 3.3.8 through 4.5.5 are vulnerable to prototype pollution via the `PUT /api/v1/runs/:runId/metadata` endpoint. The vulnerability exists because the application passes attacker-controlled `operation.key` inputs directly into the `JSONHeroPath.set()` method without sanitization. This allows an attacker possessing a valid environment API key to inject properties into `Object.prototype`, which is inherited by all objects in the webapp process. Because Trigger.dev operates as a multi-tenant web application, this pollution corrupts internal state across tenants, including Prisma query objects and Prometheus metrics. The contamination results in authentication failures for other tenants and triggers uncaught exceptions that cause the entire webapp process to crash, enabling a persistent denial-of-service attack.

## Attack Chain

1. Attacker authenticates to the Trigger.dev instance using a standard, low-privileged environment API key.
2. Attacker crafts a malicious `PUT` request to the `/api/v1/runs/:runId/metadata` endpoint.
3. The request body includes an `operation.key` value set to `$.__proto__.polluted` (or similar prototype path).
4. The `applyMetadataOperations()` function in `packages/core/src/v3/runMetadata/operations.ts` receives the untrusted key.
5. `JSONHeroPath` processes the key and executes `.set()` on the `newMetadata` object, inadvertently writing to `Object.prototype`.
6. Global process state is corrupted; subsequent database queries (e.g., via Prisma) fail because they now inherit unexpected properties.
7. Third-party libraries (e.g., Prometheus `prom-client`) encounter validation errors due to the polluted object structure, causing an `uncaughtException`.
8. The webapp process crashes, resulting in service denial for all tenants, repeating upon subsequent requests (crash-loop).

## Impact

The vulnerability enables a complete cross-tenant denial of service. A single authenticated request can crash the entire webapp process. Beyond availability, the ability to pollute `Object.prototype` serves as a primitive for further exploitation, such as logic or authentication bypasses, depending on the gadgets present in the runtime environment.

## Recommendation

- Upgrade Trigger.dev instances immediately to version 4.5.6 or later to include the prototype pollution guards.
- Audit existing logs for anomalous `PUT` requests to the metadata API containing suspicious path segments like `__proto__`, `constructor`, or `prototype`.
- Ensure that any custom middleware or API extensions for metadata processing use `Object.create(null)` for storage and implement strict allow-listing for JSON path keys.
- Implement request schema validation to strictly enforce expected character sets and patterns for API metadata keys.
