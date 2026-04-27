---
title: WeKan Missing Authorization Vulnerability in Integration REST API
slug: 2026-04-wekan-missing-auth
description: WeKan before 8.35 contains a missing authorization vulnerability in the Integration REST API endpoints, allowing authenticated board members to perform administrative actions without proper privilege verification, potentially leading to unauthorized data access and modification.
date: "2026-04-23T10:00:00Z"
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

WeKan, a collaborative Kanban board application, is vulnerable to a missing authorization issue in versions prior to 8.35. This flaw resides within the Integration REST API endpoints, where authenticated board members can execute administrative actions without sufficient privilege validation.  An attacker, if they are an authenticated user, can exploit this vulnerability to enumerate integrations, including webhook URLs, create new integrations, modify or delete existing integrations, and…
