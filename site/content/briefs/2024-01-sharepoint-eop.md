---
title: Microsoft SharePoint Server Elevation of Privilege via CVE-2023-29357
slug: 2024-01-sharepoint-eop
description: Exploitation attempts against Microsoft SharePoint Server vulnerability CVE-2023-29357, involving specific API calls and HTTP methods, can lead to privilege escalation and unauthorized access to sensitive data within the SharePoint environment.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sharepoint
  - elevation_of_privilege
  - cve-2023-29357
vendors:
  - Microsoft
products:
  - SharePoint Server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://socradar.io/microsoft-sharepoint-server-elevation-of-privilege-vulnerability-exploit-cve-2023-29357/
  - https://github.com/LuemmelSec/CVE-2023-29357/blob/main/CVE-2023-29357/Program.cs
rules:
  - title: SharePoint CVE-2023-29357 Exploitation Attempt
    description: Detects potential exploitation attempts against Microsoft SharePoint Server vulnerability CVE-2023-29357 based on specific API calls.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - windows
  - title: SharePoint CVE-2023-29357 User Agent Filter
    description: Detects potential exploitation attempts against Microsoft SharePoint Server vulnerability CVE-2023-29357 based on user agent strings seen used in exploits.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - windows
rules_count: 2
---

This brief addresses potential exploitation attempts targeting CVE-2023-29357, a Microsoft SharePoint Server elevation of privilege vulnerability. Successful exploitation could allow attackers to gain unauthorized privileged access to the SharePoint environment. The vulnerability is triggered by crafting specific API calls. The provided detection logic monitors web server logs for requests to specific SharePoint API endpoints associated with user management and current user information, specifically targeting GET requests with a 200 status code to the `/api/web/siteusers` and `/api/web/currentuser` paths. Exploitation could lead to unauthorized access to sensitive data, data theft, and further compromise of the SharePoint server, resulting in a broader security breach.

## Attack Chain

1.  The attacker identifies a vulnerable SharePoint server exposed to the internet or an internal network.
2.  The attacker crafts a malicious HTTP GET request targeting the `/api/web/siteusers` endpoint, aiming to retrieve a list of site users.
3.  The attacker sends the crafted HTTP GET request to the vulnerable SharePoint server.
4.  The SharePoint server processes the request without proper authorization checks due to the vulnerability.
5.  The server responds with a 200 OK status code, potentially returning sensitive information about site users, or granting elevated privileges.
6.  The attacker analyzes the response data, identifying privileged accounts or gaining insights into the SharePoint user structure.
7.  The attacker leverages the gained privileges to access sensitive data, modify SharePoint configurations, or further compromise the system.

## Impact

Successful exploitation of CVE-2023-29357 can lead to a complete compromise of the SharePoint server. Attackers can gain unauthorized access to confidential documents, manipulate critical business data, and potentially use the compromised server as a pivot point for further attacks within the organization's network. The impact includes data breaches, financial losses, reputational damage, and disruption of business operations.

## Recommendation

*   Deploy the provided Sigma rule to detect exploitation attempts against CVE-2023-29357 by monitoring for specific API calls (e.g., `*/_api/web/siteusers*`, `*/_api/web/currentuser*`) in web server logs.
*   Review and patch Microsoft SharePoint Servers to the latest version to remediate CVE-2023-29357, as referenced in the references section.
*   Implement network segmentation to limit the blast radius of a potential SharePoint compromise, as this helps contain lateral movement.
