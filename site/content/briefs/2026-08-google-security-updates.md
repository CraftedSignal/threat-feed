---
title: Google Security Updates — August 2026
slug: 2026-08-google-security-updates
description: Roundup of Google security advisories published in August 2026.
date: "2026-08-01T01:42:27Z"
lastmod: "2026-08-10T21:38:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - roundup
vendors:
  - Google
  - GitHub
products:
  - Google Kubernetes Engine
  - Chrome (<= 2026-08-03)
  - Google Password Manager (<= 2026-08-03)
  - Google Cloud Authenticator (<= 2026-08-03)
  - Angular compiler (< 22.0.1, < 21.2.19, < 20.3.27, <= 19.2.25)
  - Angular core (< 22.0.1, < 21.2.19, < 20.3.27, <= 19.2.25)
  - Angular (>= 22.0.0-next.0, < 22.0.2)
  - Angular (>= 21.0.0-next.0, < 21.2.19)
  - Angular (>= 20.0.0-next.0, < 20.3.27)
  - Angular (<= 19.2.25)
  - adk-python
  - Antigravity-SDK
  - github.com
  - Angular
  - ml-metadata
affected_os:
  - Windows
cves:
  - id: CVE-2026-69151
    epss: 0.00328
  - id: CVE-2026-68945
    epss: 0.00193
  - id: CVE-2026-18618
    cvss: 7.5
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_secret_access_via_unusual_user_agent.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_unusual_service_account_secret_get.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_endpoint_permission_enumeration.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_multi_resource_discovery.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_sensitive_rbac_change_followed_by_workload_modification.toml
  - https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/
  - https://github.com/advisories/GHSA-jj27-h5hq-8x99
  - https://github.com/advisories/GHSA-jhpw-976m-542j
  - https://www.securityweek.com/gemini-agent-to-agent-attack-exposed-secrets-enabled-pull-request-tampering/
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2632
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18618
updates:
  - at: "2026-08-03T17:59:17Z"
    level: L2
    summary: added CVE-2026-68945, CVE-2026-69151
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-jj27-h5hq-8x99
      - https://github.com/advisories/GHSA-jhpw-976m-542j
  - at: "2026-08-04T11:38:53Z"
    level: L1
    summary: new product
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/gemini-agent-to-agent-attack-exposed-secrets-enabled-pull-request-tampering/
  - at: "2026-08-04T13:38:08Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2632
  - at: "2026-08-10T21:38:36Z"
    level: L2
    summary: added CVE-2026-18618
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18618
---

Aggregated Google security advisories for August 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Google's August 2026 security updates.
