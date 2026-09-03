---
title: Authentication Bypass in Mendix SAML Module
slug: 2026-09-mendix-saml-bypass
description: An authentication bypass vulnerability (CVE-2026-80465) in multiple Mendix SAML module versions allows unauthenticated attackers to hijack user sessions via improper SAML response signature validation.
date: "2026-09-03T13:21:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mendix:saml:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - sso
  - mendix
vendors:
  - Mendix
products:
  - Mendix SAML (Mendix 10 compatible) (< V4.2.3)
  - Mendix SAML (Mendix 11 compatible) (< V4.2.3)
  - Mendix SAML (Mendix 9.24 compatible) (< V3.6.27)
cves:
  - id: CVE-2026-80465
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80465
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mendix SAML (Mendix 10/11 compatible) to V4.2.3 and Mendix SAML (Mendix 9.24 compatible) to V3.6.27.
      owner: IT Operations
      addresses: CVE-2026-80465
      evidence: Source explicitly identifies these versions as secure.
---

CVE-2026-80465 is a critical authentication bypass vulnerability affecting specific versions of the Mendix SAML module. The vulnerability stems from the module's failure to properly validate SAML response signatures. By exploiting this flaw, unauthenticated remote attackers can forge or manipulate SAML assertions, potentially gaining unauthorized access to user sessions within Single Sign-On (SSO) environments. This vulnerability impacts several compatibility versions of the module, specifically Mendix SAML (Mendix 10 compatible) versions prior to 4.2.3, Mendix SAML (Mendix 11 compatible) versions prior to 4.2.3, and Mendix SAML (Mendix 9.24 compatible) versions prior to 3.6.27. Defenders should prioritize patching, as successful exploitation results in complete account takeover for affected SSO configurations.

## Impact

Successful exploitation allows unauthenticated attackers to bypass authentication and hijack active user sessions. The impact is significant for organizations relying on Mendix-based SSO, potentially exposing internal applications to unauthorized access. Given the nature of authentication bypasses, the risk of broad lateral movement and unauthorized data access is high.

## Recommendation

Prioritize the upgrade of the Mendix SAML module to the secure versions specified by the vendor: upgrade Mendix SAML (Mendix 10 compatible) and (Mendix 11 compatible) to V4.2.3 or later, and Mendix SAML (Mendix 9.24 compatible) to V3.6.27 or later. Since no specific IOCs are available, SOC teams should audit authentication logs for anomalous SAML assertion patterns or unauthorized session initiation events originating from untrusted network segments.
