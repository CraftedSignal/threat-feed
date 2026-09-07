---
title: Authentication Bypass in 389 Directory Server via SASL Bind State Confusion
slug: 2026-09-07-389-directory-server-auth-bypass
description: A vulnerability in 389 Directory Server allows unauthenticated attackers to elevate privileges by exploiting state confusion during SASL authentication, leading to unauthorized Directory Manager access.
date: "2026-09-07T15:32:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:389directoryserver:389_directory_server:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-18922
  - privilege-escalation
vendors:
  - 389 Directory Server
products:
  - 389 Directory Server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker can send a SASL PLAIN bind as cn=Directory Manager with an incorrect password, then complete a SASL ANONYMOUS bind on the same connection, causing the server to grant Directory Manager authority without any valid credentials.
    confidence_band: high
cves:
  - id: CVE-2026-18922
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18922
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch 389 Directory Server to the version provided by the vendor.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-18922 remediation
  hunt_leads:
    - lead: Log sequences showing failed bind followed by successful bind
      technique_id: T1550
      data_needed:
        - Directory Server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source description of attack flow
  mitigation_plan:
    - priority: immediate
      action: Patch 389 Directory Server
      owner: IT Operations
      addresses: CVE-2026-18922
---

CVE-2026-18922 describes a critical authentication bypass vulnerability in 389 Directory Server. The issue stems from improper handling of identity state during SASL PLAIN authentication. When a bind operation fails, the server fails to properly clear the identity properties associated with the connection. A subsequent successful bind, using any SASL mechanism, allows the stale identity from the previous failed attempt to be incorrectly applied to the new security context. An attacker can deliberately trigger a failed SASL PLAIN bind as 'cn=Directory Manager' and then complete a second bind (such as an anonymous bind or a low-privileged account bind) to inherit the privileges of the identity used in the first failed attempt. This flaw grants an unauthorized attacker administrative access to the directory server without requiring valid credentials.

## Impact

Successful exploitation results in full administrative control over the 389 Directory Server. An attacker can read, modify, or delete directory data, manage users, or alter security configurations, leading to a complete compromise of the identity store and downstream systems dependent on the directory for authentication or authorization.

## Recommendation

- Monitor 389 Directory Server access logs for unusual sequences of failed bind operations followed by immediate successful binds on the same connection.
- Review directory server configuration for strict enforcement of authentication policies.
- Apply patches provided by the vendor for 389 Directory Server to resolve the identity property handling flaw.
