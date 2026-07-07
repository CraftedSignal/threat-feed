---
title: Multiple Vulnerabilities in Roundcube Webmail (CVE-2026-54432, CVE-2026-54433)
slug: 2026-07-roundcube-multi-vulnerabilities
description: Multiple vulnerabilities, including Server-Side Request Forgery (SSRF), Cross-Site Scripting (XSS), and Denial of Service (DoS), have been discovered in Roundcube Webmail versions 1.6.x prior to 1.6.17 and 1.7.x prior to 1.7.2, allowing remote attackers to impact service availability and potentially execute malicious code or access internal resources.
date: "2026-07-06T13:52:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webmail
  - vulnerability
  - ssrf
  - xss
  - dos
  - web-application
vendors:
  - Roundcube
products:
  - Roundcube Webmail < 1.6.17
  - Roundcube Webmail < 1.7.2
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0835/
  - https://roundcube.net/news/2026/07/05/security-updates-1.6.17-and-1.7.2
  - https://www.cve.org/CVERecord?id=CVE-2026-54432
  - https://www.cve.org/CVERecord?id=CVE-2026-54433
---

The CERT-FR has published an advisory regarding multiple vulnerabilities, specifically CVE-2026-54432 and CVE-2026-54433, in Roundcube Webmail versions 1.6.x prior to 1.6.17 and 1.7.x prior to 1.7.2. These vulnerabilities, announced on July 6, 2026, by CERT-FR (with Roundcube's security bulletin dated July 5, 2026), could allow a remote attacker to trigger a denial of service, perform Server-Side Request Forgery (SSRF), and inject indirect remote code (XSS). The advisory highlights the necessity for users to apply security updates to prevent potential compromise of their webmail instances and maintain the integrity and availability of their communications.

## Attack Chain

[The source does not provide specific attack chain details or observed exploitation steps beyond describing the types of vulnerabilities. Therefore, a detailed attack chain cannot be constructed.]

## Impact

Successful exploitation of these vulnerabilities (CVE-2026-54432, CVE-2026-54433) in affected Roundcube Webmail instances could lead to various detrimental outcomes. An attacker could trigger a denial of service, rendering the webmail service unavailable to legitimate users. The Server-Side Request Forgery (SSRF) vulnerability could allow an attacker to coerce the webmail server into making requests to internal or external systems on their behalf, potentially exposing sensitive information from internal network resources or enabling further network pivot points. Additionally, the Cross-Site Scripting (XSS) vulnerability could be used to execute malicious scripts in a user's browser, enabling actions such as session hijacking, defacement of the web interface, or credential theft. The exact number of victims is not specified, but any organization using vulnerable versions of Roundcube Webmail is at risk.

## Recommendation

*   Immediately apply the security updates for Roundcube Webmail, upgrading to version 1.6.17 or later for the 1.6.x branch, or version 1.7.2 or later for the 1.7.x branch, as detailed in the Roundcube security bulletin referenced in this brief.
*   Review the details of CVE-2026-54432 and CVE-2026-54433 to understand the specific risks posed by these vulnerabilities.
*   Ensure that all public-facing web applications are regularly patched and monitored for signs of compromise.
