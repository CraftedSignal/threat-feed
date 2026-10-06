---
title: Brute-Force Vulnerability in Planka TOTP Authentication
slug: 2026-10-planka-totp-brute-force
description: Planka versions 2.2.0 through 2.2.1 contain a vulnerability in the TOTP verification endpoint that lacks rate-limiting, allowing attackers with known user passwords to brute-force two-factor authentication tokens.
date: "2026-10-06T16:56:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:planka:planka:2.2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:planka:planka:2.2.1:*:*:*:*:*:*:*
tags:
  - credential-access
  - vulnerability
  - web-application
vendors:
  - Planka
products:
  - Planka (2.2.0-2.2.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Planka 2.2.0 through 2.2.1 fails to limit incorrect TOTP codes submitted to POST /api/access-tokens/..., allowing attackers to brute force two-factor authentication codes.
    confidence_band: high
cves:
  - id: CVE-2026-105835
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105835
rules:
  - title: Detect Excessive TOTP Verification Failures
    description: Detects potential brute-force attempts against the Planka /api/access-tokens/verify-totp endpoint by identifying a high volume of POST requests resulting in unsuccessful verification.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rate-limiting for /api/access-tokens/verify-totp
      owner: IT Operations
      due: 24h
      evidence: Source identifies lack of rate limiting as the core vulnerability.
  hunt_leads:
    - lead: Search logs for high frequency POST requests to the verify-totp endpoint
      technique_id: T1110.001
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Lack of rate limiting allows for automated brute force.
---

Planka versions 2.2.0 through 2.2.1 are vulnerable to a brute-force attack targeting the two-factor authentication (2FA) mechanism. The vulnerability exists within the /api/access-tokens/verify-totp endpoint, which fails to implement rate-limiting or account lockout mechanisms for failed TOTP code submissions. If an attacker has obtained a user's password, they can leverage the ten-minute pending token issued by the application to systematically guess six-digit TOTP codes. Given the lack of throttling, an attacker can exhaustively attempt combinations until the correct token is identified, ultimately resulting in unauthorized access to the victim's account. This flaw represents a significant risk for organizations relying on the native 2FA implementation in Planka, as it effectively bypasses the second layer of security.

## Attack Chain

1. Attacker obtains a valid username and password through credential harvesting or other initial access methods.
2. Attacker initiates the authentication process against the Planka instance using the compromised credentials.
3. The server validates the password and returns a ten-minute valid pending token, prompting for the second-factor code.
4. Attacker targets the /api/access-tokens/verify-totp endpoint with high-frequency HTTP POST requests.
5. Attacker iterates through six-digit TOTP code combinations within the ten-minute window allowed by the pending token.
6. The server fails to enforce rate limits or block the source IP after repeated failed attempts.
7. Upon successfully guessing the correct code, the server returns a full session access token.
8. Attacker uses the acquired access token to gain unauthorized entry to the application.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to bypass 2FA, leading to full account takeover. The impact includes the potential for unauthorized access to project management data, sensitive information exposure, and further lateral movement within the compromised environment. This vulnerability affects all deployments of Planka versions 2.2.0 and 2.2.1.

## Recommendation

Detection engineering teams should monitor web access logs for anomalous traffic patterns indicating credential stuffing or brute-forcing behavior against the specific verification endpoint.

- Monitor webserver logs for high volumes of POST requests to /api/access-tokens/verify-totp originating from a single source IP.
- Implement request rate-limiting on the Planka /api/access-tokens/verify-totp endpoint at the web application firewall (WAF) or reverse proxy level to mitigate brute-force attempts.
- Audit Planka authentication logs for an unusually high number of failed TOTP verification attempts associated with a single user account.
