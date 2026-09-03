---
title: Unauthenticated Cross-Origin WebSocket Exploitation in Taipy
slug: 2026-09-taipy-cors-misconfig
description: Taipy misconfigures its socket.io server with wildcard CORS and credentials enabled, permitting arbitrary domains to perform authenticated actions and state modifications via WebSockets without CSRF protections.
date: "2026-09-03T15:21:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:taipy:taipy:*:*:*:*:*:*:*:*
tags:
  - web-application
  - cors
  - websocket
  - crsf
  - cve-2026-85183
vendors:
  - Taipy
products:
  - Taipy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The inclusion of credential flags in the socket.io configuration allows for the misuse of authenticated sessions.
    confidence_band: high
cves:
  - id: CVE-2026-85183
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85183
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit Taipy deployment configurations for wildcard CORS settings in socket.io.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-85183 description of wildcard CORS vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict CORS origin to trusted domains and disable credential flags in socket.io configuration.
      owner: IT Operations
      addresses: CVE-2026-85183
      evidence: Vulnerability remediation path for socket.io misconfiguration.
---

Taipy versions configured with default socket.io settings are vulnerable to a critical cross-origin configuration flaw (CVE-2026-85183). The application enables both a wildcard Cross-Origin Resource Sharing (CORS) origin policy and the 'credentials' flag within its WebSocket implementation. This combination allows an attacker to host a malicious webpage that forces a victim's browser to establish a credentialed WebSocket connection to the Taipy server. Because the server trusts the origin and processes credentials, the attacker can execute unauthorized state variable modifications and trigger server-side action callbacks. This vulnerability effectively bypasses traditional CSRF protections for the WebSocket channel, potentially leading to full unauthorized control over the Taipy application instance. Defenders must note that this vulnerability resides in the application's configuration of its communication layer, which persists as long as the default socket.io policy remains in place.

## Impact

Successful exploitation allows attackers to perform unauthorized actions on behalf of authenticated users, including the modification of internal application state and the execution of server-side logic (action callbacks). This bypass of CSRF protection poses a significant risk to application integrity and data security, particularly in multi-user Taipy deployments where administrative or sensitive user actions are performed.

## Recommendation

* Prioritize an audit of Taipy WebSocket configurations to ensure the 'Access-Control-Allow-Origin' header is restricted to trusted, specific domains rather than a wildcard ('*').
* Disable the transmission of credentials (cookies/authorization headers) for cross-origin WebSocket connections if cross-domain access is required.
* Implement strict origin validation logic within the socket.io 'connection' middleware to drop any incoming requests that do not originate from expected application domains.
* Monitor application logs for WebSocket connection attempts originating from unknown or unexpected HTTP 'Origin' headers.
