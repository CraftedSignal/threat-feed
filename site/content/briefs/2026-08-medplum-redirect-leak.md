---
title: Medplum External Auth Callback Improper Redirect Validation
slug: 2026-08-medplum-redirect-leak
description: An improper redirect URI validation vulnerability in Medplum allows attackers to steal authorization codes and perform account takeover by prefix-matching registered callback URIs.
date: "2026-08-17T18:47:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - oauth
  - account-takeover
  - cve
  - webserver
vendors:
  - Medplum
products:
  - Medplum (<= 5.1.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The external identity provider callback at GET /auth/external accepts attacker-controlled redirect URIs that only need to start with a registered client redirect URI.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-m44r-7c5h-m6mj
rules:
  - title: Detects CVE-2026-53728 Exploitation - Malicious Redirect URI in Auth Callback
    description: Detects potential exploitation attempts of the Medplum redirect vulnerability by searching for anomalous redirect URIs in external authentication callback requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Medplum instance to version > 5.1.5
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-53728 remediation
    - action: Deploy Sigma detection rule to monitor /auth/external traffic
      owner: Detection Engineering
      due: 48h
      evidence: Detection of exploitation attempts
  hunt_leads:
    - lead: Search logs for unusual redirect targets in callback state parameters
      technique_id: T1190
      data_needed:
        - Web server logs for /auth/external
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source describes tampering with state.redirectUri
  mitigation_plan:
    - priority: immediate
      action: Enforce exact string equality for redirect URIs
      owner: IT Operations
      addresses: CVE-2026-53728
      evidence: Mitigation section of source
---

Medplum versions 5.1.5 and earlier contain a critical vulnerability in the external identity provider callback handler (GET /auth/external). The application performs a prefix-match (startsWith) validation on the redirect URI provided in the OAuth 'state' parameter instead of an exact-match check. An attacker can craft a malicious state object containing a redirect URI that starts with a legitimate, registered URI but resolves to an attacker-controlled origin. 

When the victim completes an external authentication flow, the Medplum server appends the 'login' and 'code' artifacts to the attacker-supplied URI and redirects the victim's browser. By injecting a custom PKCE verifier into the tampered state object, an attacker can redeem the stolen authorization code, leading to complete account takeover. This vulnerability bypasses intended OAuth security boundaries and poses a severe risk to healthcare data environments.

## Attack Chain

1. The attacker identifies a target client with an identity provider configured and a prefix-matchable redirect URI (e.g., http://callback.audit.local).
2. The attacker crafts a malicious JSON 'state' object, inserting a forged 'redirectUri' that starts with the registered prefix but points to attacker infrastructure (e.g., http://callback.audit.local.attacker.com).
3. The attacker injects a known PKCE 'code_challenge' and method into the forged 'state' object.
4. The attacker URL-encodes the tampered 'state' object for use in an OAuth request.
5. The victim is coerced or lured into initiating an external login flow using the attacker's tampered 'state' parameter.
6. Upon IdP authentication, the Medplum server triggers the vulnerable 'externalCallbackHandler', which accepts the forged 'redirectUri' due to insecure prefix matching.
7. The server redirects the victim's browser to the attacker's server, leaking the 'code' and 'login' parameters.
8. The attacker redeems the stolen 'code' at the Medplum '/oauth2/token' endpoint using their previously injected PKCE verifier to gain an access token and complete account takeover.

## Impact

Successful exploitation results in full account takeover (ATO) and unauthorized access to Protected Health Information (PHI) within the Medplum platform. The vulnerability bypasses PKCE protections and allows attackers to pivot from an open redirect to cross-origin data theft. Given the sensitivity of the data managed by Medplum, this impact could lead to significant regulatory violations and breach notification requirements under HIPAA.

## Recommendation

1. Patch all Medplum installations to a version strictly greater than 5.1.5 immediately.
2. Deploy the provided Sigma rule to webserver logs to detect requests to /auth/external containing suspicious redirect URI patterns that deviate from authorized domains.
3. Review OAuth client configurations to ensure registered redirect URIs are as specific as possible and do not allow for hostname extension via prefix matching.
