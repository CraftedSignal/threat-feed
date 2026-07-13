---
title: Decidim Vulnerability Allows Unauthorized Access to Identity Documents via Reusable Signed URLs
slug: 2026-07-decidim-auth-bypass
description: A high-severity vulnerability (CVE-2026-45378) in Decidim's identity document verification workflow allows unauthorized access to sensitive identity documents. Signed `/rails/active_storage/disk/` URLs, which are generated for administrator review, can be harvested and replayed by unauthenticated users for up to seven days, enabling attackers to bypass authentication and download highly sensitive personal information if these URLs are leaked through various channels.
date: "2026-07-13T17:15:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - access-control
  - data-leakage
  - rails
  - active-storage
  - decidim
vendors:
  - Decidim
products:
  - Decidim (decidim-verifications < 0.30.9)
  - Decidim (decidim-verifications >= 0.31.0.rc1, < 0.31.5)
  - Decidim (decidim-verifications >= 0.32.0.rc1, < 0.32.0)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over Web Service
    evidence: Anyone who obtains one of those URLs can retrieve the document until the signature expires.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-3mvf-82qp-8qh5
  - https://github.com/decidim/decidim/pull/16680
rules:
  - title: Detects CVE-2026-45378 Exploitation - Unauthorized Decidim Document Access
    description: Detects exploitation of CVE-2026-45378 in Decidim, where identity verification documents are accessed via signed Active Storage URLs without a valid authenticated session, indicating potential unauthorized data retrieval. This rule flags requests to the sensitive URI path.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - webserver
rules_count: 1
---

A significant vulnerability, identified as CVE-2026-45378, affects Decidim's identity document verification feature. This flaw allows sensitive scanned identity documents, submitted by participants and displayed in the administration workflow, to be exposed through signed `/rails/active_storage/disk/` URLs. These URLs are generated using `variant_url(...)` for `Decidim::Authorization` blobs, and their signature remains valid for approximately seven days. Crucially, these URLs can be accessed and the associated documents retrieved without any active authenticated session. This means that if an attacker obtains one of these signed links - potentially through browser history, screenshots, logs, or other leakage channels - they can bypass authentication checks and download highly sensitive personal information, posing a critical risk of data exfiltration and privacy breach for organizations utilizing Decidim's identity verification.

## Attack Chain

1. **Initial Access (Admin Account)**: An attacker or malicious insider, possessing legitimate administrator credentials, signs into the Decidim application.
2. **Navigate to Verification Review**: The attacker navigates to the administrator review page for identity documents, such as `http://localhost:3001/admin/id_documents`.
3. **Generate Signed URL**: The Decidim application renders the scanned identity document images using `variant_url(...)`, which embeds signed `/rails/active_storage/disk/...` URLs directly into the HTML of the admin review page.
4. **Harvest Signed URL**: The attacker uses browser developer tools to intercept and copy one of the generated signed `/rails/active_storage/disk/<SIGNED_TOKEN>/<FILENAME>` URLs.
5. **Exfiltrate URL**: The attacker exfiltrates this harvested URL outside the legitimate admin session, potentially via copy-paste, screenshots, or other means that may introduce the URL into logs, browser history, or other less secure channels.
6. **Unauthorized Access (Unauthenticated)**: The attacker or an unauthenticated third party uses the harvested signed URL in a private browser window or a different system, without logging into Decidim, to directly access and download the sensitive identity document.
7. **Data Retrieval**: The unauthenticated party successfully retrieves the identity document image, bypassing all authentication and authorization checks, for up to seven days while the signature remains valid.

## Impact

This vulnerability directly impacts organizations using Decidim's "Identity documents" verification feature, leading to potential unauthorized access and exfiltration of highly sensitive personal information. Any party that obtains a valid signed URL, even without authentication, can download the underlying scanned identity document for up to seven days. This significantly elevates the risk of data leakage through common channels such as browser history, screenshots, copy-pasting, support tickets, web server logs, analytics tooling, or malicious browser extensions that capture full URLs. The exposed data, being identity verification documents, typically contains personally identifiable information, making successful exploitation a critical privacy and compliance incident for affected individuals and organizations.

## Recommendation

* **Deploy the Sigma rule** in this brief to your SIEM to detect suspicious access patterns to `/rails/active_storage/disk/` endpoints, specifically looking for requests that may originate from unexpected sources or without a valid preceding authenticated session.
* **Patch CVE-2026-45378** by updating `rubygems/decidim-verifications` to versions `0.30.9` or later, `0.31.5` or later, or `0.32.0` or later, as referenced in the provided GitHub Security Advisory.
* **Implement network-level monitoring** for webserver access logs to identify any anomalous access to URL paths containing `/rails/active_storage/disk/` from external or untrusted IP addresses, or those without expected session cookies/authentication headers.
* **Consider temporarily disabling** the "Identity documents" verification feature in Decidim as a workaround until the patch for CVE-2026-45378 can be applied.
