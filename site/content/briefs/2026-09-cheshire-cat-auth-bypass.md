---
title: Authentication Bypass in Cheshire Cat AI via Custom Auth Handler
slug: 2026-09-cheshire-cat-auth-bypass
description: An unauthenticated remote code execution vulnerability in Cheshire Cat AI version 1.9.2 and earlier stems from improper validation of the user_id argument within the custom authentication handler.
date: "2026-09-13T19:26:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cheshire_cat_ai:cheshire_cat_ai:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - webserver
vendors:
  - Cheshire Cat AI
products:
  - Cheshire Cat AI (<= 1.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument user_id leads to missing authentication.
    confidence_band: high
cves:
  - id: CVE-2026-90579
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90579
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to the Cheshire Cat AI management interface at the edge firewall.
      owner: IT Operations
      due: 24h
      evidence: Remote exploitation is possible due to authentication bypass.
  hunt_leads:
    - lead: Search for unauthorized authentication attempts directed at the custom_auth_handler endpoint.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Manipulation of the user_id argument leads to missing authentication.
  mitigation_plan:
    - priority: immediate
      action: Implement IP whitelisting or VPN access for the Cheshire Cat AI instance.
      owner: IT Operations
      addresses: CVE-2026-90579
      evidence: Public disclosure makes the product vulnerable to remote exploitation.
  gaps:
    - Missing official vendor patch
---

Cheshire Cat AI version 1.9.2 and earlier contains an authentication bypass vulnerability due to flawed logic in the _authorize_http_key function located in core/cat/factory/custom_auth_handler.py. An attacker can exploit this by manipulating the user_id argument to bypass authentication mechanisms entirely. The vulnerability allows remote, unauthenticated access to the application, potentially leading to unauthorized operations within the AI framework. As the vulnerability has been publicly disclosed and the project maintainers have not yet provided a patch, installations of Cheshire Cat AI are at risk of exploitation. Defenders should monitor web server access logs for anomalous requests to API endpoints that rely on the affected custom authentication handler.

## Attack Chain

1. Attacker performs reconnaissance to identify instances of Cheshire Cat AI exposed to the internet.
2. Attacker locates the application endpoint that utilizes the core/cat/factory/custom_auth_handler.py authentication logic.
3. Attacker crafts an HTTP request targeting the affected function _authorize_http_key.
4. Attacker injects a manipulated user_id argument into the request parameters to bypass authentication checks.
5. The application fails to validate the identity of the requester, granting the attacker an authenticated session.
6. Attacker leverages the gained session to perform unauthorized API calls or interact with the AI logic.
7. Final objective is achieved, which may include data exfiltration or arbitrary command execution within the application context.

## Impact

Successful exploitation allows a remote, unauthenticated attacker to bypass authentication controls, potentially gaining full control over the Cheshire Cat AI instance. This could lead to the exposure of sensitive AI models, processed data, and underlying system commands. The vulnerability affects all users running versions 1.9.2 and earlier, as there is currently no vendor-provided patch.

## Recommendation

* Monitor web server logs for HTTP requests directed at authentication endpoints containing non-standard or unexpected user_id values.
* Implement strict network access controls to limit exposure of the Cheshire Cat AI interface to trusted networks only until a security update is released.
* Evaluate the necessity of the custom authentication handler and consider implementing external authentication proxies (e.g., OAuth2, OIDC) as an interim compensating control.
