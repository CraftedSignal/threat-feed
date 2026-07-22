---
title: Eclipse Jetty Digest Authentication Bypass via ISO-8859-1 Encoding Flaw (CVE-2026-10050)
slug: 2026-07-jetty-digest-auth-bypass
description: A vulnerability, CVE-2026-10050, in Eclipse Jetty's HTTP client `DigestAuthentication.apply()` method allows an authentication bypass by an attacker who can exploit the lossy ISO-8859-1 character encoding to forge Digest authentication response hashes for users with non-Latin-1 passwords.
date: "2026-07-22T22:56:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - authentication-bypass
  - java
  - jetty
  - iso-8859-1
  - character-encoding
  - cve
vendors:
  - Eclipse
products:
  - Jetty jetty-security (9.4.0.v20161208-9.4.58.v20250814)
  - Jetty jetty-security (10.0.0-10.0.26)
  - Jetty jetty-security (11.0.0-11.0.26)
  - Jetty jetty-security (12.0.0-12.0.35)
  - Jetty jetty-ee8-security (12.0.0-12.0.35)
  - Jetty jetty-ee9-security (12.0.0-12.0.35)
  - Jetty jetty-security (12.1.0-12.1.9)
  - Jetty jetty-ee8-security (12.1.0-12.1.9)
  - Jetty jetty-ee9-security (12.1.0-12.1.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker who knows a victim's username can bypass Digest authentication by replacing all non-Latin-1 characters in the password with `?` characters, since the collision password produces the same MD5-based Digest response hash as the original password.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2fvj-hgj9-j2gr
---

A critical vulnerability, CVE-2026-10050, has been identified in Eclipse Jetty's HTTP client, specifically within the `DigestAuthentication.apply()` method of the `jetty-security` and `jetty-eeX-security` components. The flaw stems from the incorrect use of `StandardCharsets.ISO_8859_1` encoding when computing Digest authentication response hashes. This lossy encoding silently replaces any character above U+00FF (e.g., Chinese, Japanese, Cyrillic, Arabic, Emoji) with a question mark (`?`), leading to identical hash contributions for diverse characters. An attacker with a known username can exploit this by replacing non-Latin-1 characters in a target's password with `?` characters to create a collision password, enabling them to bypass Digest authentication and impersonate the legitimate user. The vulnerability affects Jetty versions 9.4.0 through 9.4.58.v20250814, 10.0.0 through 10.0.26, 11.0.0 through 11.0.26, 12.0.0 through 12.0.35, and 12.1.0 through 12.1.9 across various security packages.

## Attack Chain

1. An attacker identifies a web application or service that utilizes Eclipse Jetty's Digest Authentication for user login.
2. The attacker obtains a valid username for a target user on the vulnerable system (e.g., via OSINT, credential stuffing, or brute-forcing usernames).
3. The attacker determines that the target user likely has a password containing non-Latin-1 characters (e.g., from an international region or using emojis).
4. The attacker crafts a "collision password" by replacing all non-Latin-1 characters (U+00FF and above) in the presumed original password with `?` characters.
5. The attacker initiates a Digest authentication attempt to the vulnerable Jetty application, providing the known username and the crafted collision password.
6. During the authentication process, the Jetty client's `DigestAuthentication.apply()` method computes MD5-based Digest response hashes using the `ISO-8859-1` character encoding.
7. Due to the lossy nature of `ISO-8859-1`, both the legitimate password and the crafted collision password (where non-Latin-1 characters are replaced by `?`) produce identical Digest response hashes.
8. The vulnerable Jetty server validates this identical Digest response hash, thereby authenticating the attacker as the legitimate user, achieving an authentication bypass.

## Impact

This vulnerability presents two significant impacts. Firstly, it allows for **authentication bypass** (CVE-2026-10050). If a service using Jetty's Digest authentication has users with passwords containing non-Latin-1 characters (e.g., Chinese, Japanese, Korean, Cyrillic, Arabic, Greek, or Latin Extended characters above U+00FF, including many accented European characters or emojis), an attacker can successfully authenticate as that user. This is achieved by knowing the username and crafting a collision password where all non-Latin-1 characters are replaced with `?`, which generates the same Digest hash. Secondly, this flaw can lead to a **denial of service for legitimate users**. Since Jetty's Digest client computes hashes using ISO-8859-1, legitimate users with non-ASCII (Latin-1+) characters in their passwords will have their bytes differ from UTF-8 hashes stored on the server side. Consequently, these legitimate users will be unable to successfully authenticate via Digest authentication, even if their password is correct, effectively locking them out of their accounts.

## Recommendation

* **Patch CVE-2026-10050** immediately by upgrading all affected Eclipse Jetty installations to fixed versions. Consult the vendor advisory for specific patch versions for `jetty-security`, `jetty-ee8-security`, and `jetty-ee9-security`.
* Avoid using Digest authentication in environments where users may have passwords containing non-Latin-1 characters. Consider migrating to stronger, less error-prone authentication mechanisms like modern token-based authentication (e.g., OAuth 2.0, OpenID Connect) or certificate-based authentication.
* Review web server access logs for repeated failed authentication attempts followed by a sudden success for accounts that typically use non-Latin-1 characters in their usernames, or for authentication attempts using unusual password patterns that might correspond to the `?` character substitution.
