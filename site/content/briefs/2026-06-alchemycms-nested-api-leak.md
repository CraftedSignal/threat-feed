---
title: 'AlchemyCMS: Unauthenticated Nested Page API Leaks Restricted & Unpublished Content'
slug: 2026-06-alchemycms-nested-api-leak
description: An unauthenticated API endpoint, `GET /api/pages/nested`, in Alchemy CMS versions up to 8.2.5 (including all 8.x versions prior to a fix and all 7.x versions up to 7.4.14), fails to enforce authorization and scoping checks, allowing any anonymous user to retrieve the complete page tree, encompassing restricted and unpublished pages, and, with `?elements=true`, the full content of these sensitive pages, completely bypassing intended access controls and leading to unauthorized information disclosure.
date: "2026-06-19T17:53:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - information-disclosure
  - cms
  - rails
  - ruby
vendors:
  - AlchemyCMS
products:
  - Alchemy CMS (>= 8.2.0, <= 8.2.5)
  - Alchemy CMS (>= 8.1.0, <= 8.1.13)
  - Alchemy CMS (>= 8.0.0.a, <= 8.0.14)
  - Alchemy CMS (<= 7.4.14)
references:
  - https://github.com/advisories/GHSA-mqq5-j7w8-2hgh
rules:
  - title: Detects Alchemy CMS /api/pages/nested metadata leak attempt
    description: Detects unauthenticated GET requests to the /api/pages/nested endpoint in Alchemy CMS, indicating an attempt to enumerate the full page tree, including metadata for restricted and unpublished pages.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1592
      - T1595
    data_sources:
      - webserver
  - title: Detects Alchemy CMS /api/pages/nested sensitive content leak attempt
    description: Detects unauthenticated GET requests to the /api/pages/nested endpoint with 'elements=true' in Alchemy CMS, indicating an attempt to exfiltrate the full content of restricted and unpublished pages.
    platform: sigma
    severity: high
    tactics:
      - collection
      - impact
    techniques:
      - T1005
      - T1567
    data_sources:
      - webserver
rules_count: 2
---

A critical information disclosure vulnerability exists within Alchemy CMS, affecting versions up to 8.2.5 (including 8.0.0.a-8.0.14, 8.1.0-8.1.13, and 8.2.0-8.2.5), and all 7.x versions up to 7.4.14. The flaw lies in the `Api::PagesController#nested` endpoint, specifically `GET /api/pages/nested`, which allows any unauthenticated user to retrieve the full internal page tree, including metadata for pages marked as restricted or unpublished. More critically, appending `?elements=true` to the request exposes the actual content of these sensitive pages, completely bypassing intended access controls. This vulnerability stems from a lack of authorization checks (`authorize!`) and proper content scoping within the `nested` action, contrasting with other API actions that correctly enforce these security measures. This can lead to the unauthorized exposure of confidential organizational data.

## Attack Chain

1.  **Target Identification**: An attacker identifies a public-facing website running a vulnerable version of Alchemy CMS through various reconnaissance methods (e.g., banner grabbing, web application scanning, or examining publicly available information).
2.  **Initial Information Gathering (Metadata)**: The attacker sends an unauthenticated `GET` request to the `/api/pages/nested` endpoint (e.g., `curl -s http://target.com/api/pages/nested`).
3.  **Discovery of Sensitive Pages**: The API response provides a JSON object containing the full page tree, including metadata for all pages. This response reveals which pages are marked as `"restricted":true` or `"public":false`, indicating content that should be hidden from anonymous users.
4.  **Targeted Content Request**: Based on the identified sensitive page metadata, the attacker constructs a new `GET` request to the same `/api/pages/nested` endpoint, this time appending the `elements=true` parameter (e.g., `curl -s "http://target.com/api/pages/nested?elements=true"`).
5.  **Exfiltration of Confidential Data**: The vulnerable Alchemy CMS application responds to this request by providing the full content (elements/ingredients) of the previously identified restricted and unpublished pages, including sensitive text like "TOPSECRET_RESTRICTED_BODY_proof123", effectively bypassing all access control mechanisms.
6.  **Impact and Analysis**: The attacker successfully obtains confidential information, intellectual property, or other sensitive data, which can then be used for competitive advantage, further system compromise, or to cause significant reputational and financial damage.

## Impact

The vulnerability allows for complete and unauthenticated information disclosure of any content stored within Alchemy CMS that has been marked as restricted or unpublished. This could include sensitive business documents, intellectual property, draft communications, private user data, or internal plans. If exploited, organizations face severe consequences such as data breaches, regulatory non-compliance, reputational damage, and financial losses due to the exposure of proprietary or confidential information. The severity is highlighted by the observed ability to leak specific "TOPSECRET_RESTRICTED_BODY_proof123" content.

## Recommendation

*   **Patch CVE-XXXX-YYYY**: Immediately upgrade your Alchemy CMS installation to a fixed version beyond 8.2.5 (e.g., 8.2.6 or later for the 8.x series) or 7.4.14 (for the 7.x series) to remediate the vulnerability described in the GHSA-mqq5-j7w8-2hgh advisory.
*   **Enable Webserver Logging**: Ensure comprehensive logging is enabled for your web server (e.g., Apache, Nginx) to capture full HTTP request details, including `cs-method`, `cs-uri-stem`, and `cs-uri-query`.
*   **Deploy Sigma Rules**: Deploy the provided Sigma rules `Detects Alchemy CMS /api/pages/nested metadata leak attempt` and `Detects Alchemy CMS /api/pages/nested sensitive content leak attempt` to your SIEM solution and tune them for your environment.
*   **Review Logs**: Proactively review historical web server logs for any past exploitation attempts matching the patterns identified in the Sigma rules.
