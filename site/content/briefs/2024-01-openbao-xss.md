---
title: OpenBao Reflected XSS Vulnerability in OIDC Authentication Error Message
slug: 2024-01-openbao-xss
description: OpenBao installations with OIDC/JWT authentication enabled and roles with `callback_mode=direct` are vulnerable to reflected XSS via the `error_description` parameter, allowing attackers to steal Web UI tokens; patched in v2.5.2.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - openbao
  - xss
  - reflected-xss
  - web-application
vendors:
  - OpenBao
products:
  - OpenBao
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-cpj3-3r2f-xj59
rules:
  - title: Detect OpenBao XSS Attempt via error_description Parameter
    description: Detects attempts to exploit the OpenBao reflected XSS vulnerability by searching for script tags or other suspicious HTML in the error_description parameter of HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenBao Direct Callback Mode Configuration
    description: Detects OpenBao roles with callback_mode set to direct which are vulnerable to XSS via the error_description parameter if using OIDC/JWT authentication.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenBao, a secrets management tool, is susceptible to a reflected XSS vulnerability (CVE-2026-33758) affecting installations using OIDC/JWT authentication methods. The vulnerability specifically impacts roles configured with `callback_mode=direct`. An attacker can exploit this flaw by injecting malicious JavaScript code via the `error_description` parameter in the authentication error page. Successful exploitation grants the attacker access to the victim's Web UI token, potentially leading to unauthorized access to sensitive secrets. The vulnerability was introduced prior to version 2.5.2 and has been patched in version 2.5.2 by replacing the dynamic `error_description` with a static error message. Defenders should either upgrade or implement the described workaround immediately.

## Attack Chain

1.  The attacker identifies an OpenBao instance with OIDC/JWT authentication enabled and at least one role configured with `callback_mode=direct`.
2.  The attacker crafts a malicious URL containing a JavaScript payload within the `error_description` parameter. Example: `/ui/login?error_description=<script>alert('XSS')</script>`.
3.  The attacker tricks a victim (e.g., an administrator logged into the OpenBao Web UI) into clicking the malicious link, perhaps via phishing or other social engineering methods.
4.  The victim's browser sends a request to the OpenBao server with the malicious `error_description` parameter.
5.  The OpenBao server reflects the attacker's JavaScript payload back to the victim's browser within the HTML of the authentication error page.
6.  The victim's browser executes the attacker-controlled JavaScript code due to the reflected XSS vulnerability.
7.  The malicious JavaScript code steals the victim's authentication token used for accessing the OpenBao Web UI.
8.  The attacker uses the stolen token to authenticate to the OpenBao Web UI and gain unauthorized access to secrets.

## Impact

Successful exploitation of this XSS vulnerability allows attackers to steal authentication tokens from legitimate OpenBao users. With a stolen token, an attacker can gain complete access to the OpenBao Web UI, allowing them to read, modify, or delete secrets, policies, and other sensitive configurations. This could lead to a complete compromise of the secrets management system, potentially affecting all applications and services that rely on OpenBao for their credentials. The severity is considered critical due to the ease of exploitation and high potential impact on confidentiality and integrity.

## Recommendation

*   Upgrade OpenBao to version 2.5.2 or later to apply the patch that replaces the vulnerable `error_description` parameter (reference: Patches section).
*   As a workaround, remove any roles configured with `callback_mode=direct` (reference: Workarounds section).
*   Implement a web application firewall (WAF) rule to detect and block requests containing suspicious JavaScript code in the `error_description` parameter (example rule below).
*   Monitor web server logs for requests with `error_description` containing `<script>` or other HTML tags commonly used in XSS attacks (reference: example rule below, logsource: webserver).
