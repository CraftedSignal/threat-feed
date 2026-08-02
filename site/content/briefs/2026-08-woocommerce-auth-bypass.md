---
title: Authentication Bypass Vulnerability in WooCommerce Social Login Plugin
slug: 2026-08-woocommerce-auth-bypass
description: The WooCommerce - Social Login plugin for WordPress contains an authentication bypass vulnerability (CVE-2026-8457) that allows unauthenticated attackers to log in as any user, including administrators, via forged Apple ID tokens.
date: "2026-08-02T01:08:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - WordPress
products:
  - WooCommerce - Social Login (<= 2.8.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Exploit Public-Facing Application
    evidence: The WooCommerce - Social Login plugin for WordPress is vulnerable to Authentication Bypass in all versions up to and including 2.8.7.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550.001
    technique_name: 'Use Alternate Authentication Material: Application Access Token'
    evidence: This makes it possible for unauthenticated attackers to log in as any existing WordPress user — including administrators — by supplying a forged id_token.
    confidence_band: high
cves:
  - id: CVE-2026-8457
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8457
---

The WooCommerce - Social Login plugin for WordPress, in versions up to and including 2.8.7, is affected by a critical authentication bypass vulnerability (CVE-2026-8457). The flaw resides in the plugin's Apple login handler, which decodes the base64 payload of an Apple id_token without performing mandatory cryptographic signature verification. Additionally, the plugin fails to validate critical JWT claims, including the issuer, audience, and expiration. 

Defenders should note that the security nonce required to initiate the login flow is exposed to unauthenticated users within a localized JavaScript object on the login page. By combining the known nonce with a crafted id_token containing a target victim's email address, an attacker can coerce the application into resolving the target account and establishing an active, authenticated session. This allows for full account takeover of any registered WordPress user, including those with administrative privileges, without requiring existing credentials.

## Impact

Successful exploitation allows unauthenticated attackers to gain unauthorized administrative access to affected WordPress installations. This leads to complete site compromise, data exfiltration, the ability to modify or delete content, and the potential for further server-side code execution via administrative plugin or theme management features. The vulnerability affects all sites running versions 2.8.7 or earlier of the WooCommerce - Social Login plugin.

## Recommendation

- Update the WooCommerce - Social Login plugin to the latest available version beyond 2.8.7 immediately.
- Review WordPress access logs for anomalous authentication events or successful logins originating from unusual IP addresses immediately following the identification of the vulnerability.
- Audit user roles and administrative accounts for any unauthorized changes or newly created accounts that may indicate post-exploitation activity.
- If patching is not immediately feasible, disable the Apple social login functionality within the plugin settings to mitigate the primary exploitation vector.
