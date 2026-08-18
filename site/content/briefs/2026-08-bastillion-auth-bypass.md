---
title: Authentication Bypass in Bastillion via Path Prefix Misrouting
slug: 2026-08-bastillion-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-75627) in Bastillion versions 5.1.0 and earlier allows unauthenticated attackers to access administrative controllers via path prefix manipulation, enabling full control over managed SSH infrastructure.
date: "2026-08-18T12:51:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - authentication-bypass
  - ssh-gateway
vendors:
  - Bastillion
products:
  - Bastillion (5.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Bastillion fails to properly validate request URI paths in its controller dispatcher, allowing unauthenticated attackers to bypass authentication filters.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Attackers can access administrative controllers to... create manager accounts, and register managed systems, gaining control over SSH access to the managed fleet.
    confidence_band: high
cves:
  - id: CVE-2026-75627
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75627
  - https://www.vulncheck.com/advisories/bastillion-authentication-bypass-via-path-prefix-routing-mismatch
  - https://github.com/bastillion-io/Bastillion/commit/d759fb686a1a097b1b026e286fd9b20e5ba349c8
rules:
  - title: Detects CVE-2026-75627 Exploitation - Authentication Bypass Attempt
    description: Detects potential exploitation of CVE-2026-75627 where an attacker attempts to bypass authentication via abnormal path prefixes directed at administrative controllers.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Bastillion to the latest version to mitigate CVE-2026-75627.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-75627 requires patching via vendor update.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the Bastillion management interface via firewall rules.
      owner: IT Operations
      addresses: CVE-2026-75627
      evidence: Administrative interface exposure allows unauthenticated exploitation.
---

Bastillion, an open-source SSH gateway, contains a critical authentication bypass vulnerability (CVE-2026-75627) in its controller dispatcher logic. The vulnerability, rooted in improper validation of request URI paths within the `BaseKontroller.java` component, allows an unauthenticated attacker to bypass authentication filters by prefixing legitimate administrative request URIs with arbitrary path segments. 

By successfully navigating this dispatcher flaw, an attacker gains unauthorized access to administrative functions. This access allows the actor to read sensitive user listings, create new manager accounts with elevated privileges, and register new managed systems within the Bastillion environment. Given Bastillion's role as a gateway for SSH access, this exploit grants attackers potential control over the entire managed server fleet. The vulnerability affects all versions of Bastillion up to and including 5.1.0. Defenders must prioritize patching, as this vulnerability allows complete compromise of the Bastillion instance without prior authentication.

## Attack Chain

1. Attacker performs reconnaissance to identify the presence of Bastillion and its administrative endpoints.
2. Attacker crafts an HTTP request targeting an administrative controller (e.g., /user/list or /manager/create).
3. Attacker prepends an arbitrary path segment to the URI, triggering the flaw in the dispatcher's authentication filter logic.
4. The Bastillion application fails to validate the manipulated URI path and treats the request as authorized.
5. Attacker executes the administrative function, such as creating a new privileged manager account.
6. Attacker authenticates with the newly created manager account.
7. Attacker uses the administrative interface to register additional managed systems or modify existing configurations.
8. Attacker leverages the compromised gateway to initiate unauthorized SSH connections to the managed backend infrastructure.

## Impact

Successful exploitation of CVE-2026-75627 results in a complete compromise of the Bastillion SSH gateway. An attacker can create administrative accounts, gain visibility into user data, and establish unauthorized persistence within the infrastructure. This allows for the exfiltration of credentials or the execution of arbitrary commands on the managed SSH fleet, potentially leading to widespread lateral movement and system takeover.

## Recommendation

* Immediately upgrade Bastillion to a patched version beyond 5.1.0 to resolve CVE-2026-75627.
* Implement strict network-level access control lists (ACLs) to restrict access to the Bastillion administrative interface to known management subnets.
* Enable web application firewall (WAF) rules to detect and block requests containing irregular path structures or suspicious path prefixes aimed at administrative controllers.
* Deploy the Sigma rules below to monitor for attempts to access internal administrative controllers from unauthorized or unauthenticated sources.
