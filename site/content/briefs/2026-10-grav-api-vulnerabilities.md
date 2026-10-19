---
title: Grav API Plugin Denial of Service and Authorization Bypass Vulnerabilities
slug: 2026-10-grav-api-vulnerabilities
description: The Grav API plugin for Grav CMS contains multiple vulnerabilities allowing unauthenticated resource exhaustion and authorized users to bypass page-level access controls.
date: "2026-10-19T22:23:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:getgrav:grav_api_plugin:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - broken-access-control
  - grav
  - cms
vendors:
  - Grav
products:
  - Grav API plugin (1.0.16-1.0.41)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Unauthenticated attackers can send small requests that each store about 560 KB to exhaust disk or APCu
    confidence_band: high
cves:
  - id: CVE-2026-112779
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112779
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Grav API plugin to version 1.0.42
      owner: IT Operations
      due: 48h
      evidence: Source notes version 1.0.42 resolves the vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade Grav API plugin to 1.0.42
      owner: IT Operations
      addresses: CVE-2026-112779
      evidence: NVD source indicates 1.0.42 as fixed version
---

The Grav API plugin (grav-plugin-api) versions 1.0.16 through 1.0.41 are affected by two critical security vulnerabilities. The first issue involves an unauthenticated resource exhaustion vulnerability in the translations endpoint. By sending requests to the GET /api/v1/translations/{lang} endpoint with varying language codes, an attacker can force the system to cache full translation dictionaries, rapidly exhausting available disk space or APCu memory. 

The second vulnerability is an authorization bypass affecting the sync and batch copy endpoints. Users possessing the api.pages.write permission can leverage these endpoints to perform operations on pages that are restricted by page-level rules. This allows for the unauthorized creation of pages or the modification of site translations. Attackers exploiting the resource exhaustion vulnerability can potentially crash the service, while those exploiting the authorization bypass can circumvent site-specific access policies to inject or modify content.

## Impact

Successful exploitation of the resource exhaustion vulnerability results in a Denial of Service (DoS) condition by filling the application cache or disk space, potentially impacting site availability. Exploitation of the authorization bypass allows users with limited 'api.pages.write' access to escalate their capabilities to perform prohibited page modifications, potentially leading to unauthorized data modification or administrative policy violation within the Grav CMS environment.

## Recommendation

- Upgrade the Grav API plugin to version 1.0.42 or later to address both the translation cache resource exhaustion and the authorization bypass in sync and batch copy endpoints.
- Audit logs for the `/api/v1/translations/` endpoint to identify high volumes of requests from single IP addresses that could indicate resource exhaustion attempts.
- Review permissions for all users assigned the `api.pages.write` capability to ensure strict adherence to the principle of least privilege, especially if the site relies on page-level access control.
