---
title: Open WebUI CORS Misconfiguration and Session Validation Vulnerability Leads to RCE
slug: 2026-05-open-webui-cors-rce
description: Open WebUI version v0.3.10 has a CORS misconfiguration and session validation issue that can lead to remote code execution due to a one-click attack against admin users.
date: "2026-05-11T14:05:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cors
  - rce
  - session-management
  - open-webui
vendors:
  - GitHub
products:
  - open-webui
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://github.com/advisories/GHSA-6xcp-7mpr-m7wm
  - https://github.com/open-webui/open-webui
  - https://securitylab.github.com
  - https://github.blog/2022-04-22-removing-the-stigma-of-a-cve/
  - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
rules:
  - title: Detect Open WebUI Function Creation via API
    description: Detects attempts to create functions in Open WebUI via the API, potentially indicative of exploit activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
  - title: Detect Open WebUI Function Toggle via API
    description: Detects attempts to toggle functions in Open WebUI via the API, potentially indicative of exploit activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability exists in Open WebUI version v0.3.10 due to a combination of CORS misconfiguration (GHSL-2024-174) and session management flaws (GHSL-2024-175). The CORS misconfiguration on multiple API endpoints allows arbitrary websites to make authenticated cross-site requests to Open WebUI. When combined with the failure to invalidate session cookies upon logout, this allows an attacker to perform a one-click attack, potentially gaining remote code execution on the Open WebUI instance.  The application, by default, runs as root within a Docker container, escalating the impact to a full container compromise.  This vulnerability affects users who have admin access to the `/api/v1/functions` endpoint, allowing execution of arbitrary code.

## Attack Chain

1. An attacker crafts a malicious website (`attacker.com`) containing JavaScript code that exploits the CORS misconfiguration.
2. The attacker lures an Open WebUI administrator to visit the malicious website.
3. The JavaScript on the attacker's website bypasses CORS restrictions due to the `allow_origins=["*"]` configuration.
4. The malicious script sends an authenticated POST request to the `/api/v1/functions/create` endpoint, creating a malicious filter. This step requires the user to have an active Open WebUI session.
5. The attacker's script then sends another POST request to `/api/v1/functions/id/{filter_id}/toggle` to activate the newly created filter, executing arbitrary code.
6. The code injected by the filter executes a command (e.g., `whoami`) and writes the output to a file (`/tmp/whoami.txt`) on the Open WebUI server.
7. Because Open WebUI reuses session cookies after logout, the attacker can potentially regain access even if the admin has logged out, provided the browser hasn't been closed.
8. The attacker achieves remote code execution on the Open WebUI server, with the potential to fully compromise the Docker container due to the default root user context.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the Open WebUI server. Given the default configuration where Open WebUI runs as root within a Docker container, this can lead to a complete compromise of the container and potentially the host system. The vulnerability affects any Open WebUI instance with an administrator who visits the malicious website, making it a widespread risk. The lack of session invalidation post-logout increases the window of opportunity for attackers, even if the admin user is no longer actively using the application.

## Recommendation

*   Modify the Open WebUI CORS configuration to remove the permissive `allow_origins=["*"]` and implement a more restrictive policy. Allow dynamic setup of allowed origins via the administration panel or a configuration file, as described in the remediation guidance for GHSL-2024-174.
*   Implement proper session invalidation upon logout. Ensure new cookies are generated for every session, and invalidate/remove previous session cookies from the browser's storage upon logout, as described in the remediation guidance for GHSL-2024-175.
*   Deploy the Sigma rule "Detect Open WebUI Function Creation via API" to identify potential exploitation attempts targeting the `/api/v1/functions/create` endpoint.
