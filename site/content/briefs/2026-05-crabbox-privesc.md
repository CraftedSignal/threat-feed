---
title: Crabbox Privilege Escalation Vulnerability (CVE-2026-8629)
slug: 2026-05-crabbox-privesc
description: Crabbox versions prior to v0.12.0 contain a privilege escalation vulnerability (CVE-2026-8629) that allows users with visibility-only access to obtain elevated agent tickets and impersonate trusted lease-side bridges via unauthorized POST requests to specific ticket endpoints.
date: "2026-05-14T20:21:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - web-application
products:
  - Crabbox (< v0.12.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-8629
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8629
rules:
  - title: Detect Crabbox Unauthorized Ticket Request
    description: Detects CVE-2026-8629 exploitation — POST requests to ticket endpoints from unauthorized users, indicating a privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
---

Crabbox versions prior to v0.12.0 are vulnerable to a privilege escalation issue (CVE-2026-8629). An attacker with shared visibility-only access can exploit this vulnerability to obtain Code, WebVNC, and Egress agent tickets. The flaw lies in the insufficient access control checks implemented on the `/v1/leases/:id/code/ticket`, `/v1/leases/:id/webvnc/ticket`, and `/v1/leases/:id/egress/ticket` endpoints. By sending POST requests to these endpoints, a low-privileged user can bypass intended access restrictions and obtain bridge-agent tickets, enabling them to impersonate trusted lease-side bridges. This vulnerability allows attackers to gain unauthorized control and access to resources they should not be able to access.

## Attack Chain

1. An attacker gains visibility-only access to a Crabbox lease.
2. The attacker identifies the vulnerable ticket endpoints: `/v1/leases/:id/code/ticket`, `/v1/leases/:id/webvnc/ticket`, and `/v1/leases/:id/egress/ticket`.
3. The attacker crafts a POST request targeting one of the vulnerable ticket endpoints.
4. The attacker sends the crafted POST request to the targeted ticket endpoint.
5. The Crabbox server, due to insufficient access control checks, grants a Code, WebVNC, or Egress agent ticket to the attacker.
6. The attacker uses the obtained agent ticket to authenticate as a trusted lease-side bridge.
7. The attacker performs actions and accesses resources that are normally restricted to users with higher privileges.

## Impact

Successful exploitation of CVE-2026-8629 allows attackers with visibility-only access to escalate their privileges within the Crabbox environment. This could lead to unauthorized access to sensitive data, modification of critical configurations, and potential compromise of the entire system. The specific impact depends on the permissions associated with the impersonated lease-side bridge and the overall Crabbox deployment.

## Recommendation

*   Upgrade Crabbox to version 0.12.0 or later to patch CVE-2026-8629.
*   Deploy the Sigma rule `Detect Crabbox Unauthorized Ticket Request` to identify potential exploitation attempts.
*   Monitor access logs for suspicious POST requests to the `/v1/leases/:id/code/ticket`, `/v1/leases/:id/webvnc/ticket`, and `/v1/leases/:id/egress/ticket` endpoints.
