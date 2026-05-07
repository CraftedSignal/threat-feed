---
title: Free5GC PCF Authentication Bypass Vulnerability
slug: 2024-01-free5gc-auth-bypass
description: Free5GC PCF versions prior to 1.4.3 are vulnerable to an authentication bypass due to missing middleware, allowing unauthenticated access to SM policy handlers and disclosure of subscriber SUPI.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - 5g
  - pcf
vendors:
  - free5gc
products:
  - pcf (< 1.4.3)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-6rgm-gr97-x3j5
rules:
  - title: Detect Unauthenticated PCF SM Policy Access
    description: Detects unauthenticated requests to the Npcf_SMPolicyControl endpoints, indicating a potential authentication bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1588.002
    data_sources:
      - webserver
      - linux
  - title: Detect PCF SM Policy Access Returning 200/201 Without Authorization
    description: Detects successful PCF SM Policy operations (200/201 status codes) without a valid authorization header, indicating a possible authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1588.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Free5GC PCF (Policy Control Function) versions prior to 1.4.3 contain an authentication bypass vulnerability (CVE-2026-42083) in the Npcf_SMPolicyControl service. The vulnerability stems from the absence of router authorization middleware for the `smPolicyGroup` route, allowing unauthenticated requests to reach sensitive SM policy handlers. An attacker able to reach the PCF SBI interface can directly invoke these handlers, potentially gaining access to subscriber identifiers including SUPI (Subscriber Permanent Identifier) and other policy context data. This issue was resolved in free5gc/pcf PR #63 by adding `RouterAuthorizationCheck` to `smPolicyGroup`.

## Attack Chain

1. An attacker identifies a vulnerable Free5GC PCF instance running a version prior to 1.4.3.
2. The attacker gains network access to the PCF SBI (Service Based Interface).
3. The attacker sends an unauthenticated HTTP POST request to `/npcf-smpolicycontrol/v1/sm-policies` to create a new SM policy.
4. The PCF, lacking proper authentication, processes the request without verifying the attacker's identity.
5. The attacker sends an unauthenticated HTTP GET request to `/npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}` to retrieve the newly created policy.
6. The PCF returns the policy context, which may contain sensitive subscriber identifiers such as `supi`.
7. The attacker exploits this vulnerability to gain unauthorized access to subscriber information and manipulate SM policies.

## Impact

This authentication bypass vulnerability allows unauthorized access to subscriber data and policy control functions within the 5G core network. If exploited, an attacker could potentially gain access to sensitive subscriber information, disrupt network services, or manipulate policy settings. Successful exploitation allows unauthorized actors to invoke Npcf_SMPolicyControl handlers directly.

## Recommendation

*   Upgrade Free5GC PCF to version 1.4.3 or later to patch CVE-2026-42083.
*   Deploy the Sigma rule `Detect Unauthenticated PCF SM Policy Access` to identify unauthenticated requests to the vulnerable endpoints.
*   Implement network segmentation to restrict access to the PCF SBI interface.
