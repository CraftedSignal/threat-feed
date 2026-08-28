---
title: Authentication Bypass in WPMU DEV Dashboard Plugin
slug: 2026-08-wpmu-dev-auth-bypass
description: An authentication bypass vulnerability in the WPMU DEV Dashboard WordPress plugin allows unauthenticated attackers to forge an administrator session by exploiting flawed HMAC validation in the Hub SSO flow.
date: "2026-08-28T09:13:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - authentication-bypass
  - cve-2026-76581
vendors:
  - WPMU DEV
products:
  - WPMU DEV Dashboard
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: This makes it possible for unauthenticated attackers... to obtain a valid HMAC... and replay it... resulting in an authenticated administrator session.
    confidence_band: high
cves:
  - id: CVE-2026-76581
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76581
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch WPMU DEV Dashboard plugin to version 5.0.2 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-76581 remediation requirement.
---

The WPMU DEV Dashboard plugin for WordPress (versions 5.0.1 and earlier) contains a critical authentication bypass vulnerability identified as CVE-2026-76581. The flaw stems from inconsistent HMAC message construction during the Hub SSO authentication process, specifically between the `wdpsso_step1` and `wdpsso_step2` AJAX actions. The plugin fails to consistently separate concatenated values within the token generation logic. 

An unauthenticated attacker can capture the signed output from the first step - which includes the token, state, redirect, and domain parameters - and manipulate the input to the second step. By moving the domain value into the redirect field, the attacker creates a payload that satisfies the validation logic in the second AJAX action, which unexpectedly omits the domain field from its verification check. Successful exploitation grants the attacker an authenticated administrator session, posing a significant risk for complete site takeover. Organizations using the WPMU DEV Dashboard with Hub SSO enabled are at risk and should prioritize immediate remediation.

## Impact

Successful exploitation of CVE-2026-76581 allows unauthenticated actors to gain full administrative control over the affected WordPress installation. This provides unrestricted access to site configurations, data, and themes, effectively bypassing all authentication controls. Given the widespread use of WPMU DEV plugins, the number of potentially affected WordPress environments is high, particularly among managed hosting services.

## Recommendation

* Update the WPMU DEV Dashboard plugin to version 5.0.2 or later immediately to resolve the flawed HMAC construction logic.
* Disable the "Hub SSO" feature if it is not currently required for administrative access while the patch process is underway.
* Audit access logs for repetitive or unusual POST requests targeting `admin-ajax.php` involving the `wdpsso_step1` and `wdpsso_step2` actions, particularly those demonstrating atypical parameter concatenation or unexpected redirects.
