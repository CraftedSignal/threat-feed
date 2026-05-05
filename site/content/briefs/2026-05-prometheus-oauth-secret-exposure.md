---
title: Prometheus Azure AD Remote Write OAuth Client Secret Exposure
slug: 2026-05-prometheus-oauth-secret-exposure
description: The client_secret field in Prometheus' Azure AD remote write OAuth configuration was exposed in plaintext via the `/-/config` HTTP API endpoint, due to being incorrectly typed as a string, potentially allowing unauthorized access to sensitive credentials.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - configuration-exposure
  - cloud
vendors:
  - GitHub
products:
  - prometheus/prometheus
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-42151
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-wg65-39gg-5wfj
rules:
  - title: Detect Access to Prometheus Configuration API
    description: Detects access to the Prometheus `/-/config` HTTP API endpoint, which could indicate an attempt to retrieve sensitive configuration data.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Process Accessing Prometheus Configuration File
    description: Detects processes other than Prometheus accessing the Prometheus configuration file, potentially indicating an attempt to steal secrets.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in Prometheus versions 0.45.2 up to 3.11.3 (excluding 3.11.3) and before 3.5.3 LTS related to the handling of the Azure AD remote write OAuth client secret. The `client_secret` field, intended to be a sensitive value, was incorrectly typed as a string instead of a `Secret`. This caused Prometheus to expose the client secret in plaintext when serving the configuration via the `/-/config` HTTP API endpoint. Any user or process with access to this endpoint could potentially view the exposed secret, leading to unauthorized access to Azure resources. This vulnerability was introduced to versions >=0.45.2 and affects versions < 0.311.3. The issue has been resolved in versions 3.11.3 and 3.5.3 LTS by correctly typing the `ClientSecret` field in `OAuthConfig` as `Secret`.

## Attack Chain

1. An attacker gains access to a Prometheus instance running a vulnerable version (>= 0.45.2 and < 0.311.3).
2. The attacker uses the `/-/config` HTTP API endpoint to retrieve the Prometheus configuration.
3. The API returns the configuration in plaintext format.
4. The attacker inspects the configuration data.
5. The attacker locates the `client_secret` field within the Azure AD remote write OAuth configuration section (`storage/remote/azuread`).
6. The client secret is exposed in plaintext within the configuration.
7. The attacker extracts the plaintext client secret.
8. The attacker uses the compromised client secret to authenticate to Azure AD and potentially gain unauthorized access to Azure resources.

## Impact

Successful exploitation of this vulnerability allows an attacker to obtain the Azure AD client secret used for remote write authentication. This compromised secret can then be used to impersonate the Prometheus instance and potentially access or modify data within the associated Azure resources. The number of affected Prometheus instances is currently unknown, but organizations utilizing Azure AD remote write with OAuth authentication are at risk.

## Recommendation

*   Upgrade to Prometheus version 3.11.3 or 3.5.3 LTS to patch CVE-2026-42151.
*   For users unable to upgrade immediately, switch to Managed Identity or Workload Identity authentication for Azure AD remote write as a workaround.
*   Monitor access to the `/-/config` HTTP API endpoint in your Prometheus instances using the provided Sigma rule to detect unauthorized attempts to retrieve the configuration.
*   Rotate the Azure AD client secret if you suspect your Prometheus instance was compromised.
