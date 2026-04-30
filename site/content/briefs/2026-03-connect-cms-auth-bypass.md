---
title: Connect-CMS Improper Authorization Vulnerability (CVE-2026-32299)
slug: 2026-03-connect-cms-auth-bypass
description: Connect-CMS versions 1.x up to 1.41.0 and 2.x up to 2.41.0 are vulnerable to improper authorization in the page content retrieval feature, potentially allowing retrieval of non-public information, addressed in versions 1.41.1 and 2.41.1.
date: "2026-03-24T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-32299
  - connect-cms
  - authorization-bypass
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Unprotected Credentials
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32299
  - https://github.com/opensource-workshop/connect-cms/security/advisories/GHSA-62ch-j6x7-722j
  - https://github.com/opensource-workshop/connect-cms/releases/tag/v1.41.1
  - https://github.com/opensource-workshop/connect-cms/releases/tag/v2.41.1
ioc_counts:
  email: 1
rules:
  - title: Detect Connect-CMS Unauthorized Page Access
    description: Detects potential unauthorized access to Connect-CMS pages due to CVE-2026-32299. Monitor for suspicious requests to page retrieval endpoints.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Connect-CMS Exploitation Attempt via Request Headers
    description: Detects potential exploitation attempts of Connect-CMS via unusual request headers.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Connect-CMS, a content management system, is susceptible to an improper authorization vulnerability (CVE-2026-32299) in versions 1.x up to 1.41.0 and 2.x up to 2.41.0. This flaw allows unauthenticated attackers to potentially retrieve non-public information through the page content retrieval feature. The vulnerability stems from a lack of proper access control checks during content retrieval. Patches are available in versions 1.41.1 and 2.41.1, released by the vendor to address this critical…
