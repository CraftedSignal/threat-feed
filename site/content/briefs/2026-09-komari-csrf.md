---
title: CSRF Vulnerability in Komari Management Interface
slug: 2026-09-komari-csrf
description: The Komari management interface lacks CSRF protections and secure cookie attributes, allowing an attacker to perform unauthorized administrative actions including arbitrary code execution.
date: "2026-09-10T00:51:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-security
  - csrf
  - komari
  - session-management
vendors:
  - Komari
products:
  - komari (< 0.0.0-20260609084633-98122fa4d110)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Komari management interface fails to implement CSRF protection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The endpoint /api/admin/task/exec allows for the execution of arbitrary shell commands on managed nodes.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-hxjg-93wc-h8p8
rules:
  - title: Detect Suspicious Administrative API Access
    description: Detects potentially unauthorized POST requests to sensitive Komari administrative endpoints, which may indicate a CSRF attempt if the source is not a trusted management host.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Komari package to version 0.0.0-20260609084633-98122fa4d110 or later
      owner: IT Operations
      due: 48h
      evidence: Source provided vulnerable version range
  hunt_leads:
    - lead: Search webserver logs for POST requests to /api/admin/ paths from unusual IP addresses
      technique_id: T1190
      data_needed:
        - webserver_access_logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The lack of CSRF tokens makes administrative endpoints vulnerable to unauthorized requests.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the specified patched version
      owner: IT Operations
      addresses: komari < 0.0.0-20260609084633-98122fa4d110
      evidence: Source advisory
---

The Komari management interface (version < 0.0.0-20260609084633-98122fa4d110) contains a significant security flaw regarding session and administrative request validation. The `session_token` cookie is generated without `Secure` or `SameSite` attributes, and all administrative API endpoints under `/api/admin/` lack CSRF token verification or Origin-based access controls. 

While modern browsers implement `SameSite=Lax` by default - which hinders cross-site POST requests - the application remains susceptible in same-origin contexts, when accessed via legacy browsers, or during Man-in-the-Middle (MitM) attacks due to the missing `Secure` flag. Successful exploitation enables unauthorized actors to perform high-impact operations, including executing shell commands via `/api/admin/task/exec`, disabling 2FA, and modifying system configurations. This vulnerability stems from inadequate middleware configuration in the underlying Gin framework implementation.

## Attack Chain

1. Attacker identifies the target instance of the Komari management console.
2. Attacker crafts a malicious payload (e.g., HTML form or JavaScript fetch request) targeting a sensitive endpoint such as `/api/admin/task/exec`.
3. Attacker lures an authenticated administrative user to a malicious site or injects the payload via existing XSS vulnerabilities in the target's environment.
4. The victim's browser initiates the unauthorized request to the Komari API.
5. The server receives the request, including the non-secure `session_token` cookie, which is automatically included by the browser if the environment does not strictly enforce `SameSite=Lax` or if it is a same-origin request.
6. The server application, lacking CSRF middleware, processes the request as legitimate, assuming it originated from the administrative interface.
7. The intended administrative operation (e.g., code execution or configuration change) is performed on the server or managed nodes.

## Impact

Successful exploitation allows attackers to bypass administrative authentication. Impacted operations include the execution of arbitrary shell commands on managed nodes, complete disabling of administrator 2FA, deletion of monitoring records, and modification of system settings. This could lead to a total compromise of the managed infrastructure and the Komari monitoring server itself.

## Recommendation

Prioritize updating the Komari package to version 0.0.0-20260609084633-98122fa4d110 or later. Ensure that webserver-level headers are configured to prevent cross-site request forgery and that the application is served exclusively over HTTPS with cookies flagged as `Secure` and `SameSite=Strict`. For detection engineering, monitor webserver access logs for anomalous POST requests to `/api/admin/` paths that do not originate from the expected internal management source IPs or authorized referrers.
