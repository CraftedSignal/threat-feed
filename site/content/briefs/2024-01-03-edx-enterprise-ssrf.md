---
title: edx-enterprise SAML Metadata SSRF Vulnerability
slug: 2024-01-03-edx-enterprise-ssrf
description: edx-enterprise versions 7.0.2 through 7.0.4 are vulnerable to server-side request forgery (SSRF) via a SAML metadata URL in the `sync_provider_data` endpoint, allowing an authenticated Enterprise Admin to trigger arbitrary HTTP requests from the server.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - saml
  - edx-enterprise
vendors:
  - edX
products:
  - edx-enterprise
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-64cv-vxpr-j6vc
  - https://github.com/openedx/openedx-platform/security/advisories/GHSA-328g-7h4g-r2m9
iocs:
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/
ioc_counts:
  url: 1
rules:
  - title: Detect Outbound Connection to AWS Metadata Endpoint
    description: Detects outbound connections to the AWS metadata endpoint, which may indicate SSRF attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Modification of SAML Metadata Source via API
    description: Detects API calls that modify the SAML metadata source, potentially indicating an SSRF attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `sync_provider_data` endpoint in `edx-enterprise` is susceptible to a server-side request forgery (SSRF) vulnerability. An authenticated user with the Enterprise Admin role can set the `metadata_source` field in `SAMLProviderConfig` to an arbitrary URL via the `SAMLProviderConfigViewSet` PATCH endpoint. Subsequently, calling the `sync_provider_data` endpoint triggers a server-side HTTP request to the specified URL. The `fetch_metadata_xml()` function, responsible for fetching the metadata, lacks proper validation, including HTTPS enforcement, IP filtering, and request timeouts, leading to the vulnerability. This issue affects `edx-enterprise` versions 7.0.2 through 7.0.4 and was introduced when SAML admin viewsets were migrated from `openedx-platform`.

## Attack Chain

1. Attacker authenticates to the edx-enterprise instance as an Enterprise Admin.
2. Attacker sends a PATCH request to the `SAMLProviderConfigViewSet` to modify the `metadata_source` to a malicious URL (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/`).
3. The server stores the malicious URL in the `SAMLProviderConfig.metadata_source` field.
4. Attacker sends a POST request to the `sync_provider_data` endpoint.
5. The `sync_provider_data` function retrieves the `metadata_source` URL from the `SAMLProviderConfig`.
6. The `fetch_metadata_xml` function is called with the malicious URL.
7. `fetch_metadata_xml` uses `requests.get()` to make an HTTP request to the attacker-controlled URL.
8. The server attempts to parse the (likely invalid) XML response. Even if parsing fails, the attacker has successfully triggered an SSRF.

## Impact

Successful exploitation of this SSRF vulnerability allows an Enterprise Admin to perform several malicious actions: steal cloud credentials by accessing instance metadata services (AWS, GCP, Azure), scan internal networks by probing hosts and ports behind the firewall, and access internal APIs not exposed to the internet. This can lead to full compromise of the cloud infrastructure and sensitive data exposure.

## Recommendation

*   Apply the recommended patch by upgrading `edx-enterprise` to a version outside the range of >= 7.0.2, <= 7.0.4 to remediate CVE-2026-42860.
*   Implement egress filtering at the network level to block outbound connections from the Open edX server to `169.254.0.0/16` and RFC 1918 ranges as mentioned in the advisory.
*   Deploy the Sigma rule "Detect Outbound Connection to AWS Metadata Endpoint" to monitor for connections to the AWS metadata service from the edx-enterprise server.
