---
title: RustFS Notification Target Admin API Authorization Bypass
slug: 2024-01-rustfs-admin-auth-bypass
description: A vulnerability in RustFS allows a non-admin user to overwrite a shared admin-defined notification target, leading to event interception and audit evasion due to missing admin-action authorization on notification target admin API endpoints.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - ssrf
  - event-interception
vendors:
  - rustfs
products:
  - rustfs
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://github.com/advisories/GHSA-pfcq-4gjr-6gjm
rules:
  - title: Detect RustFS Notification Target Manipulation
    description: Detects attempts to manipulate RustFS notification targets via the admin API, indicating a potential authorization bypass.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connection to Potential Attacker-Controlled Endpoint from RustFS
    description: Detects outbound connection to attacker controlled server based on attacker controlled endpoint
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A critical authorization bypass vulnerability exists in RustFS versions 0.0.2 and earlier, specifically within the notification target admin API endpoints (`rustfs/src/admin/handlers/event.rs`). These endpoints lack proper admin-action authorization, failing to call `validate_admin_request`. This oversight allows a non-admin user to overwrite admin-defined notification targets by name. Successful exploitation enables attackers to intercept events intended for legitimate administrators and evade audit logs. The attacker gains the ability to redirect bucket events to an attacker-controlled endpoint, potentially exfiltrating sensitive information like object keys, bucket names, user identities, and request metadata. This issue was patched in RustFS version 1.0.0-alpha.94.

## Attack Chain

1. An attacker gains access to a RustFS account with non-admin (readonly) privileges.
2. The attacker crafts a PUT request to one of the notification target admin API endpoints (e.g., to create or update a notification target).
3. The request bypasses the intended admin authorization checks due to the missing `validate_admin_request` call.
4. The attacker overwrites an existing, admin-defined notification target, replacing the legitimate endpoint with an attacker-controlled URL.
5. An S3 bucket event (e.g., object creation) occurs, triggering the notification system.
6. RustFS sends an HTTP request containing event data to the attacker-controlled URL.
7. The attacker captures the exfiltrated event data, including object keys, bucket names, user identities, and request metadata.
8. The attacker can also delete unbound targets or silently redirect events from bound targets, further evading audit detection.

## Impact

Successful exploitation of this vulnerability allows attackers to intercept sensitive data related to bucket events, potentially leading to data breaches and unauthorized access to resources. The vulnerability affects RustFS instances where non-admin users have access to the system, enabling them to manipulate notification targets intended for administrative purposes. The attacker can redirect events to an external endpoint, exposing potentially thousands of events containing sensitive information. The ability to overwrite existing notification targets allows for a persistent compromise until the vulnerability is patched.

## Recommendation

*   Upgrade RustFS to version 1.0.0-alpha.94 or later to patch the vulnerability.
*   Deploy the Sigma rule "Detect RustFS Notification Target Manipulation" to identify attempts to modify notification targets via the admin API.
*   Monitor web server logs (cs-uri-query, cs-method) for unusual activity related to the notification target admin API endpoints to detect potential exploitation attempts.
*   Implement strict access control policies to limit non-admin user access to sensitive API endpoints and resources.
