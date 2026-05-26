---
title: XWiki Platform Livetable Vulnerability Allows Password Hash Reconstruction
slug: 2026-05-xwiki-password-hash-disclosure
description: A vulnerability in XWiki Platform allows an attacker to reconstruct password hashes using 768 requests through the `LiveTableResults` macro, impacting versions prior to 18.0.0RC1, 17.10.13, 17.4.9, and 16.10.17.
date: "2026-05-26T20:23:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xwiki
  - credential-access
  - password-hash-disclosure
  - cve-2026-48048
vendors:
  - XWiki
products:
  - XWiki Platform
references:
  - https://github.com/advisories/GHSA-rh28-mqj4-8x59
  - https://jira.xwiki.org/browse/XWIKI-23875
  - https://github.com/xwiki/xwiki-platform/commit/c4442716b02ffcdaa9d5e703b1db6203e36456fa
rules:
  - title: Detect XWiki Password Hash Bit Disclosure
    description: Detects CVE-2026-48048 exploitation — suspicious requests to LiveTableResults potentially disclosing password hash bits
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
rules_count: 1
---

A vulnerability exists within the XWiki Platform's `LiveTableResults` macro that allows for the reconstruction of password hashes. This issue arises from an insufficient patch to a prior vulnerability (GHSA-5cf8-vrr8-8hjm), where attackers can still discover password hashes one bit at a time by utilizing slightly modified parameters. An attacker can retrieve the full password salt and hash of a user with approximately 768 requests. Patches addressing this vulnerability have been implemented in XWiki versions 18.0.0RC1, 17.10.13, 17.4.9, and 16.10.17. This vulnerability, tracked as CVE-2026-48048, impacts XWiki instances that have not applied the necessary security updates.

## Attack Chain

1. An attacker identifies an XWiki instance running a vulnerable version of the XWiki Platform.
2. The attacker crafts a series of HTTP requests targeting the `LiveTableResults` macro.
3. These requests are designed to extract password hash bits by exploiting the vulnerability related to password and email property exposure.
4. The attacker carefully modifies parameters within each request to isolate individual bits of the password hash.
5. By sending approximately 768 requests, the attacker systematically reconstructs the full password salt and hash.
6. The attacker uses the reconstructed password hash to attempt authentication or further attacks against the XWiki instance.
7. The attacker pivots to other user accounts using the cracked password or the original user's session.
8. The attacker gains unauthorized access to sensitive information or performs privileged actions within the XWiki platform.

## Impact

Successful exploitation of CVE-2026-48048 allows attackers to reconstruct user password hashes, potentially leading to unauthorized access to sensitive information stored within the XWiki Platform. The number of affected XWiki installations is unknown. Organizations using vulnerable versions of XWiki could experience data breaches, account compromise, and reputational damage if this vulnerability is exploited.

## Recommendation

*   Upgrade XWiki to version 18.0.0RC1, 17.10.13, 17.4.9, or 16.10.17 to remediate the vulnerability (reference: Patches section).
*   Apply the patch manually to the `XWiki.LiveTableResultsMacros` wiki page if upgrading is not immediately feasible (reference: Workarounds section).
*   Deploy the Sigma rule `Detect XWiki Password Hash Bit Disclosure` to identify attempts to exploit this vulnerability in web server logs.
*   Review web server access logs for suspicious activity related to the `LiveTableResults` macro and unusual request patterns.
*   Monitor XWiki instances for unauthorized access attempts and privilege escalation activities.
