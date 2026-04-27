---
title: Budibase XSS Leads to Account Takeover via JWT Theft
slug: 2024-01-budibase-account-takeover
description: The `budibase:auth` cookie in Budibase is set without the `httpOnly` flag, enabling attackers with XSS to steal JWTs and gain persistent access to user accounts.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - xss
  - account takeover
  - jwt
  - cookie
vendors:
  - Budibase
products:
  - Budibase (versions prior to 3.35.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-4f9j-vr4p-642r
rules:
  - title: Detect Outbound Connection Attempt with Document Cookie
    description: Detects a script attempting to exfiltrate document.cookie data.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Process Accessing document.cookie
    description: Detects processes potentially accessing the document.cookie property, indicative of credential theft attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Budibase, a low-code platform, is vulnerable to account takeover due to the insecure configuration of its authentication cookie. The `budibase:auth` cookie, which stores the JWT session token, is set without the `httpOnly` flag. This allows JavaScript, including malicious scripts injected via Cross-Site Scripting (XSS) vulnerabilities like GHSA-gp5x-2v54-v2q5, to access the cookie's contents.  An attacker exploiting this can steal the JWT and use it to impersonate the victim, gaining persistent…
