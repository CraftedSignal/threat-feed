---
title: Denial of Service Vulnerability in Keycloak Theme Localization
slug: 2026-09-keycloak-dos
description: An unauthenticated denial-of-service vulnerability in Keycloak (CVE-2026-79651) allows attackers to exhaust server memory by injecting arbitrary locale tags into an unbounded cache.
date: "2026-09-16T15:51:38Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:keycloak:keycloak:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - identity-management
vendors:
  - Keycloak
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker can exploit this by sending a large number of unique locale tags, eventually causing the server to run out of memory and crash.
    confidence_band: high
cves:
  - id: CVE-2026-79651
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79651
rules:
  - title: Detect Excessive Locale Parameter Variation
    description: Detects potential CVE-2026-79651 exploitation by tracking high frequency of requests with unique locale parameter values
    platform: sigma
    severity: high
    tactics:
      - impact
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Keycloak to the latest version once available
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-79651 remediation guidance
  hunt_leads:
    - lead: Identify source IPs sending abnormally high volumes of unique locale query parameters
      technique_id: T1499
      data_needed:
        - webserver_logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source states memory exhaustion caused by arbitrary locale tags
  mitigation_plan:
    - priority: immediate
      action: Rate limit requests containing the ui_locales parameter at the WAF or load balancer layer
      owner: IT Operations
      addresses: CVE-2026-79651
      evidence: Source identifies arbitrary parameter injection as the root cause
---

CVE-2026-79651 is a high-severity denial-of-service vulnerability located within the theme localization endpoints of the `keycloak-services` component. This component is responsible for managing authentication flows and UI themes. The vulnerability stems from improper validation and resource management, where the server accepts arbitrary, user-supplied locale tags from unauthenticated HTTP requests. These tags are subsequently stored in an in-memory cache without any capacity limits or TTL enforcement. By repeatedly submitting unique and randomized locale tags, an attacker can force the Keycloak application to populate the cache until the JVM heap is fully consumed, triggering an OutOfMemoryError and crashing the service. This attack requires no authentication and can be performed remotely against any exposed Keycloak instance, posing a significant availability risk to identity and access management infrastructures.

## Impact

Successful exploitation results in a complete denial-of-service condition for the Keycloak instance. Because Keycloak serves as a central authentication provider, an outage directly impacts all downstream applications and services relying on it for OIDC or SAML authentication, potentially locking users out of corporate systems.

## Recommendation

1. Patch Keycloak instances by updating to the version containing the fix for CVE-2026-79651 immediately upon vendor release.
2. Implement request rate limiting and monitoring on the `/realms/{realm}/protocol/openid-connect/auth` and theme-related endpoints to detect anomalous volumes of requests containing unique locale parameters.
3. Review web server or reverse proxy logs (e.g., Nginx, Apache) for high-frequency requests targeting theme localization parameters that result in 500-series server error codes.
