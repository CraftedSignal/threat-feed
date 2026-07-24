---
title: React Router RSC Mode CSRF Bypass
slug: 2026-07-react-router-csrf-bypass
description: A high-severity Cross-Site Request Forgery (CSRF) bypass vulnerability in React Router's unstable React Server Components (RSC) APIs allows for action execution before a 400 response, impacting applications utilizing these specific APIs.
date: "2026-07-24T16:51:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:shopify:react-router:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:shopify:remix-run\/react:*:*:*:*:*:node.js:*:*
tags:
  - react
  - router
  - csrf
  - web-application
  - vulnerability
vendors:
  - Remix
products:
  - react-router (>= 7.12.0, < 8.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'React Router: RSC Mode CSRF Bypass Allows Action Execution Before 400 Response'
    confidence_band: high
cves:
  - id: CVE-2026-22030
    cvss: 6.5
    epss: 0.00128
references:
  - https://github.com/advisories/GHSA-qwww-vcr4-c8h2
  - https://github.com/remix-run/react-router/blob/main/CHANGELOG.md#v830
  - https://github.com/remix-run/react-router/releases/tag/react-router@8.3.0
  - http://github.com/remix-run/react-router/pull/15311
---

A Cross-Site Request Forgery (CSRF) bypass vulnerability, identified as GHSA-qwww-vcr4-c8h2, has been discovered in specific versions of the React Router library (`npm/react-router`). This flaw, affecting versions greater than or equal to 7.12.0 and less than 8.3.0, specifically impacts applications that utilize the unstable React Server Components (RSC) APIs. This is a follow-up to a previously addressed related CSRF flow (CVE-2026-22030). An attacker can leverage this vulnerability to execute unauthorized actions within the context of an authenticated user's session. The issue allows these actions to be performed even before an expected 400 response would typically halt such attempts. Organizations using React Router with RSC APIs are at risk, as successful exploitation could lead to unauthorized data modification or other integrity compromises.

## Impact

Successful exploitation of the React Router CSRF bypass vulnerability leads to a high integrity impact on affected applications. Attackers can trick authenticated users into performing unintended actions within the application. This could result in unauthorized data manipulation, configuration changes, or other actions that compromise the trustworthiness and veracity of information managed by the vulnerable system. While the advisory does not specify observed victims or targeted sectors, any web application using the affected React Router versions with unstable RSC APIs is susceptible to this integrity compromise.

## Recommendation

* Immediately upgrade `npm/react-router` to version `8.3.0` or later, as referenced in the GitHub advisory GHSA-qwww-vcr4-c8h2, to remediate the Cross-Site Request Forgery (CSRF) bypass vulnerability.
* Review applications utilizing React Router's unstable RSC APIs to understand potential exposure and verify successful patching.
