---
title: Authentication Bypass Vulnerability in WPCOM Member Plugin
slug: 2026-10-wpcom-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-104803) in the WPCOM Member WordPress plugin allows unauthenticated attackers to hijack user sessions, including administrative accounts, by exploiting insufficient nonce and session validation in the social-login callback handler.
date: "2026-10-10T09:51:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wpcom:member:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - authentication-bypass
  - web-vulnerability
vendors:
  - WPCOM
products:
  - WPCOM Member (<= 1.7.27)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An unauthenticated attacker can issue a crafted GET request that writes an attacker-named, attacker-valued entry into the global session namespace.
    confidence_band: high
cves:
  - id: CVE-2026-104803
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104803
rules:
  - title: Detect CVE-2026-104803 Exploitation - Suspicious Callback Parameters
    description: Detects potential exploitation attempts of CVE-2026-104803 by flagging GET requests to common WordPress social-login patterns that contain suspicious or excessively long UUID and code parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch WPCOM Member to a version > 1.7.27 or disable social-login features.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-104803 vulnerability in versions up to 1.7.27.
  hunt_leads:
    - lead: Search web logs for high frequency of GET requests containing 'uuid' and 'code' parameters from single IPs.
      technique_id: T1550.002
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves repeated GET requests to the social-login callback.
  mitigation_plan:
    - priority: immediate
      action: Disable social-login handlers in WPCOM Member plugin settings.
      owner: IT Operations
      addresses: CVE-2026-104803
      evidence: The vulnerability exists in the social-login callback handler.
---

The WPCOM Member plugin for WordPress (versions 1.7.27 and below) is susceptible to a critical authentication bypass vulnerability, assigned CVE-2026-104803. The flaw resides in the social-login callback handler, which is registered on the WordPress 'init' hook. Because the plugin fails to perform nonce validation, lacks OAuth state verification, and does not enforce per-visitor namespace isolation in its session storage, the plugin is prone to session manipulation.

An unauthenticated attacker can supply crafted 'uuid' and 'code' parameters via a GET request to inject arbitrary values into the global session store. By manipulating these parameters, the attacker forces the plugin's 'weapp_new_user()' function to associate a target user's known or discoverable 'openid' with a session forged by the attacker. This allows the attacker to impersonate any user, including site administrators, and establish a legitimate authentication cookie. This vulnerability requires at least one social provider to be configured on the target site for the vulnerable code path to be active.

## Impact

Successful exploitation allows unauthenticated attackers to gain unauthorized access to any WordPress account on the affected site. If an attacker targets an account with administrative privileges and has discovered the associated social provider identifier, they can achieve full site takeover, potentially leading to unauthorized data exfiltration, malicious plugin installation, or site-wide compromise.

## Recommendation

- Upgrade the WPCOM Member plugin to a version patched against CVE-2026-104803 immediately.
- Until patching is possible, disable the social-login functionality within the WPCOM Member plugin configuration to deactivate the vulnerable callback handler.
- Review WordPress access logs for anomalous GET requests directed at the plugin's callback endpoints containing unusual 'uuid' or 'code' query strings.
- Audit existing user accounts for suspicious modifications or unauthorized login events.
