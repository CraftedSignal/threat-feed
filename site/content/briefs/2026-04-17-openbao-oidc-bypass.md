---
title: OpenBao OIDC Direct Callback Authentication Bypass Vulnerability
slug: 2026-04-17-openbao-oidc-bypass
description: OpenBao versions before 2.5.2 lack user confirmation for OIDC direct callback mode, allowing attackers to perform remote phishing and bypass authentication.
date: "2026-03-26T18:33:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - openbao
  - oidc
  - authentication-bypass
  - phishing
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-7q7g-x6vg-xpc3
rules:
  - title: Detect OpenBao Direct Callback Abuse
    description: Detects potential exploitation of the OpenBao OIDC direct callback vulnerability by monitoring web server logs for requests to the callback endpoint after successful authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect OpenBao Direct Callback Configuration
    description: Detects roles in OpenBao configured with callback_mode=direct, which are vulnerable to authentication bypass.
    platform: sigma
    severity: medium
    tactics:
      - configuration
    techniques:
      - T1580
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenBao, a secrets management tool, is vulnerable to an authentication bypass in versions prior to 2.5.2. This vulnerability stems from the lack of user confirmation when logging in via JWT/OIDC with a role configured with `callback_mode` set to `direct`. The vulnerability allows an attacker to initiate an authentication request and trick a victim into visiting a URL, which automatically logs them into the attacker's session. This constitutes a "remote phishing" attack because the attacker never directly interacts with the victim's credentials. The `direct` callback mode interacts directly with the OpenBao API, enabling the attacker to poll for a token after the victim has been authenticated and a token has been issued. The vulnerability is tracked as CVE-2026-33757.

## Attack Chain

1.  The attacker configures an OpenBao role with `callback_mode=direct`.
2.  The attacker initiates an OIDC authentication request, generating a unique URL.
3.  The attacker sends the generated URL to the victim via phishing or other social engineering methods.
4.  The victim clicks the link and authenticates through the OIDC provider. OpenBao automatically associates this authentication with the attacker's session due to the `direct` callback.
5.  OpenBao's API receives a direct callback, skipping user confirmation.
6.  OpenBao issues a token associated with the attacker's session, effectively authenticating the attacker as the victim.
7.  The attacker continuously polls the OpenBao API for the issued token.
8.  The attacker retrieves the token and gains unauthorized access to secrets and resources managed by OpenBao, impersonating the victim.

## Impact

Successful exploitation of this vulnerability allows an attacker to impersonate a legitimate user within OpenBao. This can lead to unauthorized access to sensitive data, including secrets, credentials, and other protected resources. The impact is critical as it allows complete bypass of intended authentication mechanisms, potentially affecting all users and systems managed by the vulnerable OpenBao instance. This can lead to data breaches, service disruption, and privilege escalation.

## Recommendation

*   Upgrade OpenBao to version 2.5.2 or later to apply the patch that introduces a confirmation screen for `direct` type logins.
*   As a workaround, remove any OpenBao roles configured with `callback_mode=direct`.
*   Enforce confirmation for every session on the token issuer side for the Client ID used by OpenBao, mitigating the risk even if roles with `callback_mode=direct` exist.
*   Monitor web server logs for unusual patterns of requests to the OpenBao OIDC callback endpoint after authentication, using the "Detect OpenBao Direct Callback Abuse" Sigma rule to identify potential exploitation attempts.
*   Deploy the "Detect OpenBao Direct Callback Configuration" Sigma rule to identify roles configured with the vulnerable `callback_mode=direct` setting.
