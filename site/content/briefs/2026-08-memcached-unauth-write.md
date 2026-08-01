---
title: Unauthorized Memcached Data Manipulation via CVE-2026-29093
slug: 2026-08-memcached-unauth-write
description: Unauthorized actors can leverage the lack of native authentication in Memcached to perform data manipulation or session hijacking, as identified in CVE-2026-29093.
date: "2026-08-01T01:42:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:wwbn:avideo:*:*:*:*:*:*:*:*
tags:
  - network-security
  - memcached
  - cve-2026-29093
  - impact
vendors:
  - Memcached
products:
  - Memcached
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: An unauthorized writer can overwrite session tokens, poison cached application content, or alter security-sensitive state.
    confidence_band: high
cves:
  - id: CVE-2026-29093
    cvss: 8.1
    epss: 0.0049
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29093
  - https://attack.mitre.org/techniques/T1565/001/
  - https://www.elastic.co/docs/reference/integrations/network_traffic
rules:
  - title: Detect First Time Seen Memcached Writer
    description: Detects the first observed client-to-server Memcached storage command, which may indicate unauthorized data manipulation or session poisoning (CVE-2026-29093).
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1565.001
    data_sources:
      - network_connection
rules_count: 1
---

Memcached is a high-performance, distributed memory object caching system that, by default, operates without authentication. This architectural design makes it susceptible to abuse if exposed to untrusted networks. An attacker with network reachability to a Memcached instance can issue storage commands - such as `set`, `add`, `replace`, `append`, `prepend`, or `cas` - to inject, overwrite, or poison cached data. This vulnerability, tracked as CVE-2026-29093, enables attackers to manipulate application state, overwrite session tokens to facilitate hijacking, or alter security-sensitive information cached in memory. Because Memcached does not require authentication, there is often no audit trail for these write operations, making detection dependent on network-level monitoring of unauthorized or anomalous client-to-server traffic.

## Attack Chain

1. Attacker performs network reconnaissance to identify accessible Memcached instances (typically port 11211).
2. Attacker verifies the Memcached version and accessibility by sending non-destructive commands like `stats`.
3. Attacker discovers existing keys within the cache using commands like `get` or `lru_crawler` to identify targets for manipulation (e.g., session prefixes).
4. Attacker constructs a malicious payload containing the manipulated data or forged session token.
5. Attacker executes a store command (`set`, `add`, `replace`) from a non-authorized client IP to the target server.
6. The Memcached server accepts the command as valid, overwriting the legitimate cached data with the attacker's payload.
7. The target application retrieves the poisoned data from the cache during its normal processing lifecycle.
8. Application executes using the manipulated data, leading to session hijacking, unauthorized access, or logic bypass.

## Impact

Successful exploitation allows for the compromise of user sessions, modification of critical application content, and potential privilege escalation. The scope of impact is limited to the data cached within the instance, but this often includes sensitive session identifiers, credentials, and business logic state. Organizations relying on Memcached for session management are at highest risk, as token forgery can grant attackers unauthorized access to active user accounts.

## Recommendation

* Block all unauthorized client access to Memcached listeners at the network layer and enforce strict access control lists.
* Bind Memcached instances to internal, private interfaces rather than public or exposed networks.
* Disable the use of the UDP protocol for Memcached if it is not explicitly required for operation to prevent amplification or injection vectors.
* Deploy network-based detection to monitor for 'first-time seen' write operations from unusual client IPs, as documented in the detection logic below.
* Ensure that cached sensitive values are protected and not captured by network sensors to prevent secondary information exposure.
