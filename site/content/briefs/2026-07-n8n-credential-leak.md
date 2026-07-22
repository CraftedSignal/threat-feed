---
title: n8n Shared Credential Leakage via HTTP Request Pagination Vulnerability
slug: 2026-07-n8n-credential-leak
description: An authenticated n8n user with 'use-only editor access' can exploit CVE-2026-59209 in shared workflows when `N8N_EXPRESSION_ENGINE=vm` is enabled, allowing them to read sensitive HTTP Header Auth credentials from the `$request.headers` object within a paginated HTTP Request node's expression and exfiltrate them, bypassing credential domain restrictions.
date: "2026-07-22T21:56:24Z"
lastmod: "2026-07-22T22:00:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:n8n:n8n:*:*:*:*:community:node.js:*:*
  - cpe:2.3:a:n8n:n8n:*:*:*:*:enterprise:node.js:*:*
  - cpe:2.3:a:n8n:n8n:2.28.0:*:*:*:community:node.js:*:*
  - cpe:2.3:a:n8n:n8n:2.28.0:*:*:*:enterprise:node.js:*:*
tags:
  - n8n
  - vulnerability
  - credential-access
  - data-exfiltration
  - application-security
  - prototype-pollution
  - authentication-bypass
  - data-enumeration
vendors:
  - n8n GmbH
products:
  - 'n8n (Vulnerable: < 1.123.61)'
  - 'n8n (Vulnerable: >= 2.28.0, < 2.28.1)'
  - 'n8n (Vulnerable: >= 2.0.0-rc.0, < 2.27.4)'
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An authenticated member with use-only editor access to a shared workflow could read credential-populated headers exposed via the `$request` object inside an HTTP Request node's pagination expression.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This can be leveraged to bypass authentication, allowing unauthenticated requests to be treated as a privileged user and exposing endpoints such as the user and project listings.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: allowing unauthenticated requests to be treated as a privileged user
    confidence_band: med
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: exposing endpoints such as the user and project listings. As a result, every account's personal data (email, role, MFA status) and all projects on the instance may be disclosed to unauthenticated callers.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The pollution can also corrupt global state, making parts of the instance unresponsive until restarted.
    confidence_band: high
cves:
  - id: CVE-2026-59209
    cvss: 6.5
    epss: 0.00294
references:
  - https://github.com/advisories/GHSA-q3j5-8vrg-4p9q
  - https://github.com/advisories/GHSA-75qm-gp28-rcq9
updates:
  - at: "2026-07-22T22:00:04Z"
    level: L2
    summary: 'merged source coverage: n8n Prototype Pollution Vulnerability Enables Unauthenticated User and Project Enumeration (CVE-2026-59206)'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-75qm-gp28-rcq9
---

A high-severity vulnerability, CVE-2026-59209, exists in the n8n workflow automation platform, allowing authenticated users with "use-only editor access" to leak sensitive credentials. This flaw occurs in instances where the `N8N_EXPRESSION_ENGINE` environment variable is set to `vm` and shared workflows utilize HTTP Request nodes with `HTTP Header Auth` credentials and pagination enabled. Attackers can craft malicious expressions within the pagination settings of such nodes to access and extract the `HTTP Header Auth` secret from the `$request.headers` object. The extracted secret can then be embedded into item data and subsequently exfiltrated via another HTTP Request node, effectively bypassing credential domain restrictions. This vulnerability impacts n8n versions prior to 1.123.61, versions 2.28.0 through 2.28.1, and versions 2.0.0-rc.0 through 2.27.4.

## Attack Chain

1. An authenticated n8n user with "use-only editor access" gains access to a shared workflow.
2. The n8n instance is configured with `N8N_EXPRESSION_ENGINE=vm`.
3. The shared workflow contains an HTTP Request node that uses `HTTP Header Auth` credentials and has pagination enabled.
4. The malicious user identifies this configuration and crafts an arbitrary expression within the pagination settings.
5. This crafted expression is evaluated and accesses the `$request.headers` object, which contains the sensitive `HTTP Header Auth` secret.
6. The expression extracts the secret and copies it into the workflow's item data.
7. The item data, now containing the credential secret, is sent to a subsequent HTTP Request node configured to exfiltrate data to an attacker-controlled external endpoint.
8. The sensitive `HTTP Header Auth` credential is exfiltrated, bypassing n8n's credential domain restrictions.

## Impact

The successful exploitation of CVE-2026-59209 allows lower-privileged, authenticated users to gain unauthorized access to sensitive `HTTP Header Auth` credentials. This enables them to bypass intended credential domain restrictions, potentially leading to unauthorized access to external services or systems integrated with n8n. The vulnerability can facilitate data exfiltration if the compromised credentials provide access to sensitive data sources. This issue affects specific configurations of n8n and poses a significant risk to organizations using shared workflows with credential-populated headers.

## Recommendation

* Upgrade n8n instances immediately to remediate CVE-2026-59209. Affected versions are `< 1.123.61`, `>= 2.28.0, < 2.28.1`, and `>= 2.0.0-rc.0, < 2.27.4`.
* Restrict workflow sharing to fully trusted users only to mitigate the risk of CVE-2026-59209.
* Avoid sharing credentials with use-only access to untrusted users, especially on workflows that employ HTTP Request nodes with pagination enabled.
