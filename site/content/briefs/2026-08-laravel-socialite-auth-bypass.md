---
title: Authentication Bypass in Laravel Socialite Facebook Provider
slug: 2026-08-laravel-socialite-auth-bypass
description: An authentication bypass vulnerability in Laravel Socialite's Facebook provider allows attackers to replay valid OIDC tokens due to missing nonce validation.
date: "2026-08-15T00:14:41Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Laravel
products:
  - Socialite
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An unauthenticated attacker can perform an authentication bypass by replaying a previously captured, valid id_token.
    confidence_band: high
cves:
  - id: CVE-2026-73683
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73683
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch CVE-2026-73683
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-73683
  hunt_leads:
    - lead: Monitor userFromToken endpoint for high frequency or anomalous token submission patterns
      technique_id: T1550.002
      data_needed:
        - Web server logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The system does not verify the association between the token and the original user session.
---

Laravel Socialite's Facebook provider contains an authentication bypass vulnerability, identified as CVE-2026-73683, stemming from a lack of nonce claim validation in the getUserByOIDCToken() function within FacebookProvider.php. OpenID Connect (OIDC) relies on the nonce claim to bind an ID token to a specific client session, preventing replay attacks. Because the implementation fails to perform this comparison, an attacker who obtains a valid, unexpired id_token issued for the same Facebook App ID can submit the token to the application's userFromToken() endpoint. The application performs successful signature, audience, and issuer validation but fails to verify session-bound uniqueness, allowing the attacker to masquerade as the legitimate user. This flaw significantly impacts services relying on Laravel Socialite for OAuth and OIDC authentication, potentially leading to widespread account takeover.

## Attack Chain

1. Attacker monitors network traffic or intercepts OIDC id_tokens issued for a target Facebook App ID.
2. Attacker successfully captures a valid, unexpired id_token intended for a victim session.
3. Attacker identifies the target application's userFromToken() OIDC callback endpoint.
4. Attacker crafts a malicious HTTP request to the target endpoint, inserting the captured id_token into the token parameter.
5. The Laravel Socialite FacebookProvider backend receives the request and executes getUserByOIDCToken().
6. The backend performs standard cryptographic validation (signature, iss, aud), which succeeds.
7. The backend neglects to perform nonce validation, treats the replayed token as a legitimate new authentication request.
8. The application establishes a session for the attacker, granting access to the victim's account.

## Impact

Successful exploitation allows unauthenticated attackers to hijack user sessions without requiring victim credentials or interaction. This vulnerability affects any application utilizing the Laravel Socialite Facebook provider, creating a high risk of unauthorized access, sensitive data exposure, and account takeover across impacted sectors.

## Recommendation

* Immediately audit applications using Laravel Socialite to determine if the Facebook provider is active and if the environment is susceptible to OIDC token replay.
* Apply vendor-provided patches or update Laravel Socialite to a version that enforces nonce validation in FacebookProvider.php as indicated by CVE-2026-73683.
* Implement additional server-side session controls and log monitoring for the userFromToken() endpoint to identify spikes in token submission originating from unexpected sources or mismatched session parameters.
