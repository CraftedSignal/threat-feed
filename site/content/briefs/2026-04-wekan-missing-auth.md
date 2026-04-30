---
title: WeKan Missing Authorization Vulnerability in Integration REST API
slug: 2026-04-wekan-missing-auth
description: WeKan before 8.35 contains a missing authorization vulnerability in the Integration REST API endpoints, allowing authenticated board members to perform administrative actions without proper privilege verification, potentially leading to unauthorized data access and modification.
date: "2026-04-23T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wekan
  - missing-authorization
  - rest-api
  - privilege-escalation
vendors:
  - WeKan
products:
  - WeKan
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41454
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41454
  - https://github.com/wekan/wekan/commit/2cd702f48df2b8aef0e7381685f8e089986a18a4
  - https://github.com/wekan/wekan/releases/tag/v8.35
  - https://www.vulncheck.com/advisories/wekan-missing-authorization-via-integration-rest-api
iocs:
  - type: url
    value: https://github.com/wekan/wekan/commit/2cd702f48df2b8aef0e7381685f8e089986a18a4
  - type: url
    value: https://github.com/wekan/wekan/releases/tag/v8.35
  - type: url
    value: https://www.vulncheck.com/advisories/wekan-missing-authorization-via-integration-rest-api
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Detect WeKan Integration API Abuse
    description: Detects potential abuse of WeKan Integration REST API endpoints by non-admin users.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect WeKan Integration Webhook Enumeration
    description: Detects GET requests to the `/api/integration` endpoint which could be used to enumerate integrations, including webhooks.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WeKan, a collaborative Kanban board application, is vulnerable to a missing authorization issue in versions prior to 8.35. This flaw resides within the Integration REST API endpoints, where authenticated board members can execute administrative actions without sufficient privilege validation.  An attacker, if they are an authenticated user, can exploit this vulnerability to enumerate integrations, including webhook URLs, create new integrations, modify or delete existing integrations, and manage integration activities. The root cause is insufficient authorization checks within the JsonRoutes REST handlers. Successful exploitation can lead to unauthorized access to sensitive information and modification of board configurations.

## Attack Chain

1. An attacker gains valid credentials for a WeKan board member account.
2. The attacker authenticates to the WeKan application via the standard login procedure.
3. The attacker sends a crafted HTTP request to the `/api/integration` endpoint without proper administrative privileges.
4. Due to missing authorization checks, the request is processed, and the attacker is able to enumerate existing integrations, including sensitive webhook URLs.
5. The attacker crafts another HTTP request to the `/api/integration` endpoint to create a new, malicious integration (e.g., a webhook that sends data to an external attacker-controlled server).
6. The attacker modifies existing integrations to redirect data flow to attacker-controlled endpoints.
7. The attacker deletes legitimate integrations, disrupting board functionality.
8. The attacker manages integration activities, potentially triggering malicious actions or gaining further information.

## Impact

Successful exploitation of this vulnerability allows an attacker to perform administrative actions on WeKan boards without proper authorization. This can lead to the exposure of sensitive webhook URLs, unauthorized modification or deletion of integrations, and the creation of malicious integrations for data exfiltration or disruption. The CVSS v3.1 score of 8.3 indicates a high severity vulnerability with significant potential for data compromise and system impact. The number of affected WeKan installations is currently unknown, but organizations using WeKan for project management and collaboration are at risk.

## Recommendation

*   Upgrade WeKan to version 8.35 or later to patch CVE-2026-41454, addressing the missing authorization vulnerability as detailed in the [reference links](#references).
*   Deploy the Sigma rule "Detect WeKan Integration API Abuse" to identify potential exploitation attempts against the Integration REST API endpoints, monitoring webserver logs for unusual API requests.
*   Review and restrict access rights for WeKan board members, ensuring that only authorized personnel have administrative privileges to minimize the attack surface as outlined in the [overview](#overview).
*   Monitor webserver logs for requests to `/api/integration` with methods like POST, PUT, and DELETE originating from non-admin users.
