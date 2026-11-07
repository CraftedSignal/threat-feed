---
brief_id: brief-2026-11-07-sonicwall-sslvpn-bypass
event_id: brief-2026-11-07-sonicwall-sslvpn-bypass
revision: 2
activity_at: "2026-11-07T07:25:03Z"
revision_history:
  - revision: 2
    at: "2026-11-07T07:25:03Z"
    checksum: sha256:c43b7af1bb5182b7a037a4c062e6168ed01d04d749a976da4d40e2533881c566
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/sonicwall-sonicos-sslvpn-saml-bypass-cve-2026-19868
title: 'SonicWall SonicOS SSLVPN: SAML authentication bypass (CVE-2026-19868)'
slug: 2026-11-sonicwall-sslvpn-bypass
description: SonicWall SonicOS SSLVPN is vulnerable to a single-factor authentication flaw that may allow users with valid credentials for an alternate authentication method to bypass SAML authentication and SAML-enforced MFA.
date: "2026-11-07T02:58:42Z"
lastmod: "2026-11-07T07:24:24Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:sonicwall:sonicos_sslvpn:*:*:*:*:*:*:*:*
vendors:
  - SonicWall
products:
  - SonicOS SSLVPN
  - SonicOS (Gen7 <= 7.3.3-7015)
  - SonicOS (Gen8 <= 8.2.2-8015)
cves:
  - id: CVE-2026-19868
    kev_status: "false"
  - id: CVE-2026-82308
    kev_status: unknown
  - id: CVE-2026-107154
    kev_status: unknown
  - id: CVE-2026-107155
    kev_status: unknown
  - id: CVE-2026-19703
    kev_status: unknown
  - id: CVE-2026-77708
    kev_status: unknown
  - id: CVE-2026-77709
    kev_status: unknown
references:
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19868
  - https://www.cve.org/CVERecord?id=CVE-2026-19868
  - https://pwn.watch/i/sonicwall-sonicos-sslvpn-saml-bypass-cve-2026-19868
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82308
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107154
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107155
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19703
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77708
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77709
updates:
  - at: "2026-11-07T07:24:24Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/sonicwall-sonicos-sslvpn-saml-bypass-cve-2026-19868
---

SonicWall SonicOS SSLVPN contains a use of single-factor authentication vulnerability (CVE-2026-19868). This vulnerability may allow a user with valid credentials for an alternate authentication method to bypass SAML authentication controls and SAML-enforced multi-factor authentication (MFA). Stakeholders are advised to apply mitigations in accordance with vendor instructions and CISA BOD 26-04 guidance.
