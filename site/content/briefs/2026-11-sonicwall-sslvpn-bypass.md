---
brief_id: brief-2026-11-07-sonicwall-sslvpn-bypass
event_id: brief-2026-11-07-sonicwall-sslvpn-bypass
revision: 1
activity_at: "2026-11-07T02:58:42Z"
title: 'SonicWall SonicOS SSLVPN: SAML authentication bypass (CVE-2026-19868)'
slug: 2026-11-sonicwall-sslvpn-bypass
description: SonicWall SonicOS SSLVPN is vulnerable to a single-factor authentication flaw that may allow users with valid credentials for an alternate authentication method to bypass SAML authentication and SAML-enforced MFA.
date: "2026-11-07T02:58:42Z"
type: advisory
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
cves:
  - id: CVE-2026-19868
    kev_status: "false"
references:
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19868
  - https://www.cve.org/CVERecord?id=CVE-2026-19868
---

SonicWall SonicOS SSLVPN contains a use of single-factor authentication vulnerability (CVE-2026-19868). This vulnerability may allow a user with valid credentials for an alternate authentication method to bypass SAML authentication controls and SAML-enforced multi-factor authentication (MFA). Stakeholders are advised to apply mitigations in accordance with vendor instructions and CISA BOD 26-04 guidance.
