---
brief_id: brief-2026-10-20-a2a-java-sdk-redirect
event_id: brief-2026-10-20-a2a-java-sdk-redirect
revision: 1
activity_at: "2026-10-20T23:53:24Z"
title: 'A2A Java SDK: Android synchronous POST credential disclosure via insecure redirect (CVE-2026-111765)'
slug: 2026-10-a2a-java-sdk-redirect
description: The A2A Java SDK for Android fails to properly disable HTTP redirects in synchronous POST requests, allowing sensitive authentication tokens to be leaked to unauthorized authorities following a 302 redirect.
date: "2026-10-20T23:53:24Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:a2a_project:a2a_java_sdk_http_client_android:*:*:*:*:*:*:*:*
tags:
  - cve-2026-111765
  - vulnerability
  - android
  - credential-theft
vendors:
  - A2A Project
products:
  - a2a-java-sdk-http-client-android (1.3.0.Final, 1.3.1.Final)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.001
    subtechnique_name: Spearphishing Attachment
    evidence: The demonstrated impact is disclosure of a complete API key or authentication token to a different authority.
    confidence_band: med
cves:
  - id: CVE-2026-111765
    cvss: 7.5
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-4fpj-g9jf-9rgg
  - https://github.com/a2aproject/a2a-java/security/advisories/GHSA-9rhm-2h4x-jwmx
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade a2a-java-sdk-http-client-android to 1.3.2.Final or later
      owner: IT Operations
      due: 48h
      evidence: The smallest compatible change is to change private boolean followRedirects = true to false.
  hunt_leads:
    - lead: Application logs showing unexpected 200 responses for POST requests that should have received a 302 redirection.
      technique_id: T1566
      data_needed:
        - Application server-side logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: 'On unpatched current main, the default test fails with: Android synchronous POST must retain the documented no-redirect default expected: <302> but was: <200>'
  mitigation_plan:
    - priority: immediate
      action: Set followRedirects = false in the synchronous POST builder.
      owner: IT Operations
      addresses: CVE-2026-111765
      evidence: Source advisory remediation guidance
---

The A2A Java SDK for Android (versions 1.3.0.Final and 1.3.1.Final) contains a critical regression where synchronous POST requests ignore previously implemented security patches to disable HTTP redirects. While the `AndroidA2AHttpClient.createConnection()` method correctly initializes connections with `setInstanceFollowRedirects(false)`, the synchronous POST builder explicitly overrides this setting with `followRedirects = true`. 

When an application uses this SDK to communicate with a compromised or malicious remote agent, the client may follow an unauthorized 302 redirect. Because the redirect process on Android's repackaged OkHttp implementation preserves nonstandard request headers, the SDK inadvertently forwards sensitive credentials - specifically those under `X-API-Key`, `API-Key`, `X-Auth-Token`, and `X-Authentication` - to the attacker-controlled destination. This vulnerability represents an incomplete remediation of the security property defined in the A2A Project's security model, which mandates that automatic redirects must be disabled to prevent credential leakage.

## Attack Chain

1. The victim application initiates a synchronous HTTP POST request using the `a2a-java-sdk-http-client-android` library.
2. The `AuthInterceptor` injects sensitive authentication tokens into the request headers.
3. The `AndroidA2AHttpClient.post()` method executes, establishing a connection that defaults to `followRedirects = true`.
4. The client contacts a malicious or compromised remote agent.
5. The attacker-controlled server responds with a 302 HTTP status code and a location header pointing to an attacker-controlled endpoint.
6. The `AndroidA2AHttpClient` automatically follows the redirect.
7. The Android OkHttp internal engine preserves the authentication headers while stripping the standard `Authorization` header during the cross-authority transition.
8. The attacker-controlled endpoint receives and logs the victim's authentication credentials.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive API keys or authentication tokens to an attacker-controlled authority. This vulnerability affects any Android application utilizing the `a2a-java-sdk-http-client-android` component (v1.3.0.Final through v1.3.1.Final). While the report does not demonstrate subsequent system compromise or remote code execution, it confirms the leakage of synthetic credentials to ephemeral loopback listeners, confirming the feasibility of token theft in production environments.

## Recommendation

Prioritized, concrete actions for developers and security teams:

* Patch the A2A Java SDK by modifying the synchronous POST builder to set `followRedirects = false` as the default, consistent with the security model for other client implementations.
* Audit applications using the `a2a-java-sdk-http-client-android` library to ensure they are not relying on automated redirect behavior for POST requests.
* Rotate any credentials that may have been exposed through this mechanism if the application has interacted with untrusted or compromised A2A remote agents.
* Verify patch application by running the `AndroidA2AHttpClientRedirectTest` fixture to ensure the `followRedirects(false)` property is strictly enforced during synchronous operations.
