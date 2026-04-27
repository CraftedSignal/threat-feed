---
title: OpenBao OIDC Direct Callback Authentication Bypass Vulnerability
slug: 2026-04-17-openbao-oidc-bypass
description: OpenBao versions before 2.5.2 lack user confirmation for OIDC direct callback mode, allowing attackers to perform remote phishing and bypass authentication.
date: "2026-03-26T18:33:37Z"
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

OpenBao, a secrets management tool, is vulnerable to an authentication bypass in versions prior to 2.5.2. This vulnerability stems from the lack of user confirmation when logging in via JWT/OIDC with a role configured with `callback_mode` set to `direct`. The vulnerability allows an attacker to initiate an authentication request and trick a victim into visiting a URL, which automatically logs them into the attacker's session. This constitutes a "remote phishing" attack because the attacker…
