---
title: FUXA Unauthenticated Project Data Disclosure Vulnerability
slug: 2026-05-fuxa-data-disclosure
description: FUXA v1.3.0-2773 is vulnerable to unauthenticated project data disclosure (CVE-2026-47717) via the /api/project endpoint, exposing sensitive configuration data like scripts and device settings, even with security enabled.
date: "2026-05-27T22:53:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - unauthenticated-access
  - data-disclosure
  - ics
  - scada
vendors:
  - FrangoTeam
products:
  - FUXA v1.3.0-2773
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-q3w6-q3hc-c5x6
  - CVE-2026-47717
rules:
  - title: Detect FUXA Unauthenticated Project Data Access
    description: Detects unauthenticated access to the FUXA /api/project endpoint, potentially indicating CVE-2026-47717 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect FUXA Project Data Retrieval with No User-Agent
    description: Detects requests to the FUXA /api/project endpoint without a User-Agent header, which may indicate automated access attempts associated with CVE-2026-47717 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

FUXA v1.3.0-2773, a SCADA/HMI platform, suffers from an unauthenticated data disclosure vulnerability. The vulnerability resides in the `/api/project` endpoint, which, despite employing a security middleware (`secureFnc`), inadvertently permits access to sensitive project configuration data to unauthenticated users. This is due to the `verifyToken` function within `server/api/jwt-helper.js` automatically generating a valid guest JWT when no token is provided. This allows attackers to bypass intended access controls and retrieve sensitive project information. Successful exploitation could expose server-side scripts, device configurations, HMI views, and alarm definitions, potentially aiding further targeted attacks within industrial environments. The vulnerability is identified as CVE-2026-47717.

## Attack Chain

1.  An attacker sends an HTTP GET request to the `/api/project` endpoint of a FUXA v1.3.0-2773 instance.
2.  The `secureFnc` middleware is triggered, aiming to verify user authentication.
3.  The `verifyToken` function in `server/api/jwt-helper.js` is invoked by the middleware.
4.  Since the attacker does not provide a token, the `verifyToken` function automatically generates a valid guest JWT signed with the server's secret.
5.  The server validates the auto-generated guest token, granting access as if the user were authenticated.
6.  The request proceeds to the `getProject` function, which retrieves the full project data.
7.  The `_filterProjectPermission` function filters UI elements for non-admin users but does not remove scripts, devices, alarms, or other sensitive configuration data.
8.  The attacker receives a JSON response containing sensitive project configuration data, including server-side scripts, device configurations, HMI views, and alarm definitions, enabling them to gain insights into the system's internal automation logic and structure.

## Impact

Successful exploitation of this vulnerability (CVE-2026-47717) allows an unauthenticated attacker to access sensitive project configuration data on a vulnerable FUXA v1.3.0-2773 instance. This exposure includes server-side scripts, device connection details, HMI configurations, and alarm definitions. In industrial control system (ICS) environments, this information can be leveraged to facilitate further targeted attacks, potentially leading to unauthorized system access, data manipulation, or disruption of critical processes.

## Recommendation

*   Apply appropriate access controls to prevent unauthenticated access to the `/api/project` endpoint in FUXA installations.
*   Monitor web server logs for requests to the `/api/project` endpoint without valid authentication tokens. Deploy the Sigma rule `Detect FUXA Unauthenticated Project Data Access` to identify such attempts.
*   Upgrade to a patched version of FUXA that addresses CVE-2026-47717.
*   Implement network segmentation to limit the impact of potential breaches.
*   Review and restrict permissions associated with guest accounts to minimize data exposure.
