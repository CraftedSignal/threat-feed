---
title: Google Security Updates — August 2026
slug: 2026-08-google-security-updates
description: Roundup of Google security advisories published in August 2026.
date: "2026-08-01T01:42:27Z"
lastmod: "2026-08-03T17:59:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - roundup
vendors:
  - Google
products:
  - Google Kubernetes Engine
  - Chrome (<= 2026-08-03)
  - Google Password Manager (<= 2026-08-03)
  - Google Cloud Authenticator (<= 2026-08-03)
  - Angular compiler (< 22.0.1, < 21.2.19, < 20.3.27, <= 19.2.25)
  - Angular core (< 22.0.1, < 21.2.19, < 20.3.27, <= 19.2.25)
affected_os:
  - Windows
cves:
  - id: CVE-2026-69151
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_secret_access_via_unusual_user_agent.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_unusual_service_account_secret_get.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_endpoint_permission_enumeration.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_multi_resource_discovery.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_sensitive_rbac_change_followed_by_workload_modification.toml
  - https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/
  - https://github.com/advisories/GHSA-jj27-h5hq-8x99
updates:
  - at: "2026-08-01T01:42:29Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_secret_access_via_unusual_user_agent.toml
  - at: "2026-08-03T11:55:38Z"
    level: L1
    summary: OS windows
    sources:
      - unit42
    source_urls:
      - https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/
  - at: "2026-08-03T17:59:17Z"
    level: L2
    summary: added CVE-2026-69151
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-jj27-h5hq-8x99
---

Aggregated Google security advisories for August 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Google's August 2026 security updates.
