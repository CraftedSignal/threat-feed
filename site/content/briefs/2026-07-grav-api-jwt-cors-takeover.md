---
title: CVE-2026-58656 - Grav API Plugin Cross-Origin Authentication Bypass and Account Takeover
slug: 2026-07-grav-api-jwt-cors-takeover
description: 'A critical vulnerability, CVE-2026-58656, in the Grav API plugin before v1.0.0-rc.16 allows unauthenticated attackers to perform fully authenticated cross-origin API requests by leveraging leaked JWT tokens via the `?token=` URL query parameter and the `Access-Control-Allow-Origin: *` response header, potentially leading to persistent backdoor super-admin accounts and sensitive data exfiltration.'
date: "2026-07-08T14:25:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - grav
  - api-plugin
  - jwt
  - cors
  - remote-code-execution
  - web-vulnerability
vendors:
  - getgrav
products:
  - Grav API plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'Grav API plugin before v1.0.0-rc.16 accepts JWT tokens via the ?token= URL query parameter and responds with Access-Control-Allow-Origin: *, allowing unauthenticated attackers to make fully authenticated cross-origin API requests from any malicious website.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Attackers who obtain a leaked JWT token ... can create persistent backdoor super-admin accounts
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: exfiltrate sensitive configuration and user data.
    confidence_band: high
cves:
  - id: CVE-2026-58656
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58656
  - https://github.com/getgrav/grav/security/advisories/GHSA-hqm9-5xxw-4qxp
  - https://www.vulncheck.com/advisories/grav-api-plugin-cross-origin-admin-account-takeover-via-cors-wildcard-and-jwt-query-parameter
rules:
  - title: Detects CVE-2026-58656 Exploitation Attempt - Grav API Token via URL
    description: Detects attempts to exploit CVE-2026-58656 where attackers send API requests to Grav with JWT tokens embedded in the 'token=' URL query parameter, indicating an authentication bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A significant vulnerability, identified as CVE-2026-58656, affects the Grav API plugin versions prior to v1.0.0-rc.16. This flaw enables unauthenticated attackers to bypass authentication and execute fully authenticated API requests from any malicious web domain. The core issue lies in the plugin's acceptance of JSON Web Tokens (JWT) directly via the `?token=` URL query parameter and its incorrect configuration of the `Access-Control-Allow-Origin: *` response header, which permits cross-origin requests. Attackers can obtain these sensitive JWT tokens through various means, including leaked access logs, proxy logs, browser history, or Referrer headers. Successful exploitation allows for the creation of persistent backdoor super-admin accounts, granting full control over the Grav instance, and facilitating the exfiltration of sensitive configuration and user data, posing a severe risk to data integrity and confidentiality for affected Grav installations.

## Attack Chain

1. **Token Leakage:** An attacker obtains a valid JWT token through passive reconnaissance, such as scraping public access logs, exploiting proxy log misconfigurations, or analyzing browser history and Referrer headers that inadvertently expose the `?token=` parameter.
2. **Malicious Website Setup:** The attacker sets up a malicious website or leverages an existing compromised site to host their exploit code.
3. **Cross-Origin Request Initiation:** From the malicious website, the attacker crafts and initiates a JavaScript-based cross-origin API request targeting the vulnerable Grav instance.
4. **JWT Injection:** The attacker embeds the leaked JWT token directly into the URL query string of the API request, using the format `/api/endpoint?token=JWT_VALUE`.
5. **Vulnerable Processing:** The Grav API plugin, due to the `Access-Control-Allow-Origin: *` header, processes this cross-origin request as fully authenticated and ignores origin restrictions.
6. **Admin Account Creation:** The attacker sends an authenticated API request to create a new, persistent super-admin account, establishing a backdoor.
7. **Data Exfiltration:** Using the newly created super-admin account or directly via the compromised JWT, the attacker sends subsequent API requests to exfiltrate sensitive configuration files and user database contents.

## Impact

The successful exploitation of CVE-2026-58656 leads to severe consequences, primarily affecting the confidentiality, integrity, and availability of Grav installations. Attackers can gain complete administrative control over the Grav content management system by creating persistent backdoor super-admin accounts. This level of access allows for arbitrary data modification, content defacement, or complete deletion. Furthermore, attackers can exfiltrate sensitive data, including but not limited to user credentials, personal identifiable information (PII), and proprietary configuration settings. This can result in significant data breaches, reputational damage, and potential regulatory non-compliance for affected organizations.

## Recommendation

* **Patch CVE-2026-58656 immediately** by upgrading the Grav API plugin to version v1.0.0-rc.16 or later to remove the vulnerable functionality.
* **Deploy the Sigma rules in this brief** to your SIEM to detect attempts to exploit the `?token=` query parameter.
* **Review web server logs and proxy logs** for instances of `/api/*?token=` query parameters to identify potential historical exploitation or token leakage.
