---
title: Open Redirect Vulnerability in better-auth via trustedOrigins Bypass
slug: 2026-08-better-auth-bypass
description: The better-auth library contains a vulnerability in its trustedOrigins validation logic that allows attackers to perform open redirects and steal sensitive tokens by manipulating the callbackURL parameter.
date: "2026-08-01T13:51:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication
  - web-security
  - open-redirect
  - cve-2025-71403
products:
  - better-auth (< 1.1.20)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can construct malicious callbackURL parameters that pass origin checks and trigger open redirects to steal sensitive tokens for account takeover.
    confidence_band: high
cves:
  - id: CVE-2025-71403
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71403
  - https://github.com/better-auth/better-auth/security/advisories/GHSA-vp58-j275-797x
  - https://www.vulncheck.com/advisories/better-auth-before-open-redirect-via-trustedorigins-bypass
---

The authentication library better-auth is vulnerable to an open redirect flaw in versions prior to 1.1.20 due to improper validation of the 'trustedOrigins' logic. This security weakness allows attackers to bypass origin checks for absolute URLs and wildcard domains. By crafting a malicious 'callbackURL' parameter, an attacker can coerce the application into redirecting users to an attacker-controlled domain. This redirection is typically used to facilitate phishing campaigns or to intercept authentication tokens during the OAuth flow, eventually leading to account takeover. The vulnerability highlights a critical failure in the validation of redirect destinations, which is a common vector for credential and session token theft in modern web applications.

## Attack Chain

1. Attacker identifies a target web application utilizing an outdated version of better-auth (below 1.1.20).
2. Attacker crafts a malicious URL containing a crafted 'callbackURL' parameter designed to bypass the 'trustedOrigins' whitelist.
3. Attacker distributes the link to an authenticated user via phishing, social engineering, or a malicious third-party site.
4. The victim clicks the link, initiating a legitimate request to the vulnerable application.
5. The application's server-side logic fails to validate the 'callbackURL' properly due to the flaw in the 'trustedOrigins' implementation.
6. The application performs an HTTP 302 redirect, sending the victim's browser, along with any sensitive session or authentication tokens, to the attacker-controlled destination.
7. Attacker captures the tokens from the referral header or URL parameters on the malicious site.
8. Attacker uses the stolen tokens to impersonate the victim and perform an account takeover.

## Impact

Successful exploitation leads to the potential theft of authentication tokens, granting attackers unauthorized access to user accounts. This impacts any web application integrating better-auth for authentication flows. While the number of affected organizations is broad, the impact is localized to users of the specific web applications that have not yet updated to version 1.1.20 or later. Unauthorized access can result in data exfiltration, service disruption, and loss of user trust.

## Recommendation

1. Upgrade better-auth to version 1.1.20 or higher immediately to resolve the vulnerable 'trustedOrigins' validation logic as specified in CVE-2025-71403.
2. Audit application logs for abnormal redirect patterns or high frequencies of requests to uncommon domains originating from authentication callback endpoints.
3. Implement strict Content Security Policy (CSP) headers to restrict where the browser is permitted to navigate during authentication redirects.
4. Review and harden all redirect validation logic across the web application, ensuring that only expected, pre-validated domains are accepted in callback parameters.
