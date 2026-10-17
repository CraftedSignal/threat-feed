---
title: Reflected Cross-Site Scripting in PAYCOMET for WooCommerce
slug: 2026-10-paycomet-xss
description: PAYCOMET for WooCommerce versions 5.45 and earlier are vulnerable to reflected cross-site scripting (XSS), allowing unauthenticated attackers to execute arbitrary scripts in the context of a victim's session.
date: "2026-10-17T21:53:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:paycomet:paycomet_for_woocommerce:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-application-vulnerability
  - ecommerce
vendors:
  - PAYCOMET
products:
  - PAYCOMET for WooCommerce (n/a - 5.45)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in PAYCOMET PAYCOMET for WooCommerce paytpv-for-woocommerce allows Reflected XSS.
    confidence_band: high
cves:
  - id: CVE-2026-109701
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109701
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade PAYCOMET for WooCommerce plugin to a version later than 5.45
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-109701 vulnerability scope
  mitigation_plan:
    - priority: immediate
      action: Upgrade PAYCOMET for WooCommerce to the latest secure version
      owner: IT Operations
      addresses: CVE-2026-109701
      evidence: NVD vulnerability scope
---

PAYCOMET for WooCommerce, a payment gateway integration for the WooCommerce platform, contains a critical input neutralization vulnerability identified as CVE-2026-109701. The flaw exists due to improper validation of user-supplied input during web page generation. This reflected cross-site scripting (XSS) vulnerability permits an attacker to craft malicious URLs containing injected script payloads. When a victim, such as an administrator or authenticated user, interacts with the manipulated link, the injected script executes within their browser session. This can lead to unauthorized actions performed on behalf of the user, potential credential theft, or session hijacking. The issue affects all versions of the plugin up to and including version 5.45. Defenders should prioritize updating the plugin to the latest version to mitigate this risk, as reflected XSS remains a primary vector for account takeover in e-commerce environments.

## Impact

Successful exploitation of CVE-2026-109701 allows unauthenticated attackers to execute arbitrary JavaScript in the context of an end-user's session. In the context of an e-commerce store using WooCommerce, this could allow attackers to steal session cookies, capture administrative credentials, or manipulate payment transaction displays. The vulnerability poses a significant risk to the integrity of the checkout process and the security of user sessions for any store running the PAYCOMET plugin.

## Recommendation

- Update the PAYCOMET for WooCommerce plugin to the latest version, ensuring it is beyond version 5.45, as documented in the vendor release notes for CVE-2026-109701.
- Audit web application logs for HTTP requests containing suspicious script tags or JavaScript event handlers in URL parameters directed at the WooCommerce store.
- Implement a strict Content Security Policy (CSP) to restrict the execution of inline scripts and unauthorized external domains, which can mitigate the impact of reflected XSS vulnerabilities.
