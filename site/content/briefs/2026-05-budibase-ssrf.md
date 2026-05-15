---
title: Budibase REST Datasource SSRF via HTTP Redirect Bypass (CVE-2026-45715)
slug: 2026-05-budibase-ssrf
description: Budibase is vulnerable to server-side request forgery (SSRF) via HTTP redirects in the REST datasource integration, allowing authenticated Builders to bypass IP blacklists and access internal services.
date: "2026-05-15T17:54:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - budibase
  - cve-2026-45715
vendors:
  - Budibase
products:
  - '@budibase/server (< 3.38.1)'
  - Budibase
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-fgqv-jh4g-pvg2
iocs:
  - type: ip
    value: 169.254.169.254
  - type: ip
    value: 0.0.0.0
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/
ioc_counts:
  ip: 2
  url: 1
rules:
  - title: Detect Budibase SSRF via REST Datasource to Metadata Endpoint
    description: Detects CVE-2026-45715 exploitation - Budibase REST datasource queries targeting cloud metadata endpoints after a redirect.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Budibase SSRF via REST Datasource Redirect
    description: Detects CVE-2026-45715 exploitation - Budibase REST datasource queries with redirects (301/302) to potential internal services.
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

Budibase is susceptible to a server-side request forgery (SSRF) vulnerability within its REST datasource integration. This flaw allows an authenticated "Builder" user to bypass the built-in IP blacklist and access internal network resources. The vulnerability stems from the `_req()` method in `packages/server/src/integrations/rest.ts` not re-checking the IP blacklist after an HTTP redirect, an oversight previously addressed in the automation steps (`fetchWithBlacklist` in `packages/server/src/automations/steps/utils.ts`). By setting up an attacker-controlled server to redirect requests to internal services or cloud metadata endpoints, an attacker can steal sensitive information. This issue was confirmed on Budibase v3.34.6, with a fix released in version 3.38.1. This poses a significant risk to cloud environments where Budibase instances are deployed, as it can lead to credential theft and unauthorized access to internal resources.

## Attack Chain

1. The attacker sets up a redirect server (e.g., using Python's `http.server`) on a publicly accessible IP address, configured to redirect to an internal service or cloud metadata endpoint.
2. An authenticated "Builder" user in Budibase creates a REST datasource, configuring it to point to the attacker's redirect server.
3. The Builder initiates a query using the newly created REST datasource. The request includes the attacker's server URL in the `path` field of the query configuration.
4. Budibase's `_req()` method in `packages/server/src/integrations/rest.ts` performs an initial IP blacklist check on the attacker's server URL. Because the attacker's server is public, this check passes.
5. The `fetch()` function follows the HTTP redirect (301/302/307) to the internal target specified by the attacker's server (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/`). Critically, this redirect is NOT re-checked against the IP blacklist.
6. The request is sent to the internal target, bypassing the intended security control.
7. The internal target (e.g., cloud metadata service) responds with sensitive information.
8. Budibase receives the response from the internal target and displays it to the Builder user, effectively leaking sensitive information like cloud IAM credentials or allowing access to internal services.

## Impact

The vulnerability allows attackers to bypass the IP blacklist and access internal services, leading to potential data breaches. On cloud instances, attackers can steal IAM credentials from metadata endpoints like `169.254.169.254`. Successful exploitation enables access to internal services such as CouchDB (`:4005`), Redis (`:6379`), and MinIO (`:4004`). This SSRF vulnerability was previously fixed in automation steps (commits `6cfa3bcca3`, `e7d47625be`) but not in the REST datasource integration, highlighting a critical oversight.

## Recommendation

*   Upgrade Budibase to version 3.38.1 or later to patch CVE-2026-45715.
*   Deploy the Sigma rule "Detect Budibase SSRF via REST Datasource to Metadata Endpoint" to detect exploitation attempts targeting cloud metadata endpoints.
*   Deploy the Sigma rule "Detect Budibase SSRF via REST Datasource Redirect" to detect exploitation attempts redirecting to internal services.
*   Review and audit existing REST datasource configurations for any suspicious URLs that may point to external or unexpected internal targets.
