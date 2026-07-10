---
title: PayloadCMS Puck Plugin Access Control Bypass Vulnerability
slug: 2024-01-03-payload-puck-access-control-bypass
description: A critical vulnerability in @delmaredigital/payload-puck versions prior to 0.6.23 allows attackers to bypass collection-level access controls in PayloadCMS via the /api/puck/* endpoints due to improper access configuration, leading to unauthorized data manipulation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - payloadcms
  - puck
  - access-control-bypass
  - cve-2026-39397
vendors:
  - Delmare Digital
  - PayloadCMS
products:
  - payload-puck plugin
  - PayloadCMS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1213
    technique_name: Data from Information Repositories
cves:
  - id: CVE-2026-39397
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39397
rules:
  - title: Detect Unauthorized Access to PayloadCMS Puck Endpoints
    description: Detects unauthorized attempts to access or manipulate data via the /api/puck/* endpoints in PayloadCMS, exploiting the access control bypass vulnerability in @delmaredigital/payload-puck versions prior to 0.6.23.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
  - title: Detect PayloadCMS Puck Plugin API Request
    description: Detects POST requests to the /api/puck/* endpoints, which might indicate exploitation of the access control bypass vulnerability in vulnerable versions of the @delmaredigital/payload-puck plugin.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The @delmaredigital/payload-puck plugin, designed to integrate the Puck visual page builder with PayloadCMS, contains a critical access control vulnerability. In versions prior to 0.6.23, the `/api/puck/*` CRUD endpoint handlers, registered by `createPuckPlugin()`, call Payload's local API with `overrideAccess: true` by default. This configuration effectively bypasses all collection-level access control mechanisms defined within PayloadCMS. Consequently, any access options passed to `createPuckPlugin()` or access rules defined on Puck-registered collections are silently ignored, granting unauthorized access to data and potentially enabling malicious actors to perform CRUD operations without proper authentication or authorization. This vulnerability allows for defense evasion and unauthorized data modification within PayloadCMS instances utilizing vulnerable versions of the plugin. It is crucial to upgrade to version 0.6.23 or later to mitigate this risk.

## Attack Chain

1.  An attacker identifies a PayloadCMS instance running a vulnerable version of the `@delmaredigital/payload-puck` plugin (prior to 0.6.23).
2.  The attacker crafts a malicious HTTP request targeting a `/api/puck/*` endpoint, such as `/api/puck/pages/create`, `/api/puck/pages/update`, or `/api/puck/pages/delete`.
3.  The attacker injects unauthorized data or commands within the request body, exploiting the lack of access control checks.
4.  The `createPuckPlugin()` function processes the request, calling Payload's local API with `overrideAccess: true`.
5.  PayloadCMS's access control mechanisms are bypassed due to the `overrideAccess` setting.
6.  The attacker's unauthorized data or commands are executed, potentially creating, updating, or deleting sensitive data within the PayloadCMS instance.
7.  The attacker may escalate privileges by modifying user roles or creating new administrative accounts via the exposed API endpoints.
8.  The attacker exfiltrates sensitive data or defaces the website.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass access controls and perform unauthorized CRUD operations on PayloadCMS collections. This could lead to data breaches, data manipulation, privilege escalation, and complete compromise of the affected PayloadCMS instance. The impact is particularly severe for organizations relying on PayloadCMS to manage sensitive content or critical business processes. The CVSS v3.1 base score is 9.4, indicating a critical severity.

## Recommendation

*   Upgrade the `@delmaredigital/payload-puck` plugin to version 0.6.23 or later to remediate the access control bypass vulnerability (CVE-2026-39397).
*   Deploy the provided Sigma rule "Detect Unauthorized Access to PayloadCMS Puck Endpoints" to identify potential exploitation attempts targeting the `/api/puck/*` endpoints.
*   Review and audit existing PayloadCMS access control configurations to ensure proper restrictions are in place after upgrading the `@delmaredigital/payload-puck` plugin.
