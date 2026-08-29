---
title: Authentication Bypass in SAML Single Sign On - SSO Login Plugin for WordPress
slug: 2026-08-saml-sso-bypass
description: An unauthenticated authentication bypass vulnerability in the SAML Single Sign On - SSO Login plugin allows attackers to overwrite the IdP signing certificate and forge administrative sessions.
date: "2026-08-29T19:41:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:saml_single_sign_on_sso_login:*:*:*:*:*:*:*:*
tags:
  - cve-2026-75807
  - authentication-bypass
  - wordpress
vendors:
  - WordPress
products:
  - SAML Single Sign On – SSO Login (<= 5.4.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: This makes it possible for unauthenticated attackers to overwrite the plugin's stored IdP signing certificate with an attacker-controlled value, and subsequently forge SAML assertions.
    confidence_band: high
cves:
  - id: CVE-2026-75807
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75807
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade SAML Single Sign On - SSO Login plugin to a patched version beyond 5.4.6.
      owner: IT Operations
      due: 24h
      evidence: Plugin version 5.4.6 and below are vulnerable per NVD.
  mitigation_plan:
    - priority: immediate
      action: Patch plugin to the latest available stable release.
      owner: IT Operations
      addresses: CVE-2026-75807
      evidence: Source advisory recommends update to patch vulnerability.
---

The SAML Single Sign On - SSO Login plugin for WordPress (versions 5.4.6 and earlier) contains a critical authentication bypass vulnerability (CVE-2026-75807). The flaw resides in the mo_saml_login_validate() Assertion Consumer Service (ACS) handler. When processing an incoming SAMLResponse, the plugin extracts an X.509 certificate and persists it into the mo_saml_required_certificate configuration option before the digital signature verification is fully enforced. The underlying mo_saml_find_certificate() function returns false when a fingerprint mismatch occurs, but it fails to halt the execution of the handler. This allows an unauthenticated remote attacker to submit a crafted SAMLResponse containing a malicious certificate. The plugin erroneously accepts and saves the attacker's certificate as the trusted IdP signing certificate. With this configuration overwritten, the attacker can subsequently forge arbitrary SAML assertions for any WordPress user account, including those with administrative privileges, leading to full site takeover.

## Attack Chain

1. Attacker monitors for target WordPress sites using the vulnerable SAML Single Sign On - SSO Login plugin.
2. Attacker crafts a malicious SAMLResponse containing an attacker-controlled X.509 certificate.
3. Attacker submits the crafted SAMLResponse to the ACS URL of the vulnerable WordPress plugin.
4. The mo_saml_login_validate() handler processes the incoming request and extracts the attacker's malicious certificate.
5. The plugin saves the malicious certificate into the mo_saml_required_certificate database option due to insufficient validation logic.
6. The site administrator receives a test_config_error_wpsamlerr004 error message during routine configuration testing, signaling a state change.
7. Attacker uses the now-trusted malicious certificate to sign and submit a forged SAML assertion for an administrative user.
8. WordPress accepts the forged assertion as valid, granting the attacker a fully privileged administrative session.

## Impact

Successful exploitation of this vulnerability results in full administrative takeover of the WordPress instance. An attacker can gain unauthorized access to any account, modify site content, exfiltrate sensitive data, or install malicious plugins to establish persistence. This vulnerability affects any organization utilizing the SAML Single Sign On - SSO Login plugin for identity management.

## Recommendation

Prioritize patching the SAML Single Sign On - SSO Login plugin for WordPress. Immediately upgrade to a version later than 5.4.6, as per official vendor releases. Detection teams should review web server logs for irregular POST requests directed at the SAML ACS endpoint containing unexpected certificate content or suspicious identity assertion patterns.

## Rules

title: "Detect CVE-2026-75807 Exploitation - Malicious SAMLResponse Submission"
description: "Detects exploitation attempts against the SAML Single Sign On - SSO Login plugin by monitoring for POST requests to the ACS handler that trigger configuration errors."
logsource:
 category: "webserver"
detection:
 selection:
 cs-method: "POST"
 cs-uri-stem|contains: "/saml-sso-login"
 filter:
 sc-status: "200"
 condition: selection and not filter
level: "high"
tags:
 - "attack.initial_access"
 - "attack.t1550.001"
falsepositives:
 - "Legitimate configuration errors or failed SSO logins by users with misconfigured IdP certificates"
tests:
 positive:
 - name: "Malicious SAMLResponse trigger"
 data:
 - cs-method: "POST"
 cs-uri-stem: "/saml-sso-login/acs"
 sc-status: "500"
 negative:
 - name: "Successful legitimate SSO login"
 data:
 - cs-method: "POST"
 cs-uri-stem: "/saml-sso-login/acs"
 sc-status: "302"
handoff:
 detection_confidence: "medium"
 required_telemetry:
 - log_source: "webserver"
 event_or_channel: "HTTP request logs"
 required_fields:
 - "cs-method"
 - "cs-uri-stem"
 - "sc-status"
 availability: "available"
 notes: "Requires standard web server access logs capturing request URI and status codes."
 validation:
 status: "needs_environment_validation"
 steps:
 - "Review logs for frequent 500-level errors on the SAML plugin ACS path."
 expected_telemetry: "HTTP 500 responses associated with the plugin ACS URI."
 pass_criteria: "Detection of spikes in failed authentication attempts during plugin configuration."
 known_evasions:
 - "Attacker might use randomized endpoints or proxying to hide the origin."
 limitations:
 - "Detection relies on the presence of error codes, which may be suppressed or logged differently."
 tuning:
 - source: "Normal SSO activity"
 guidance: "Baseline the volume of failed SSO attempts to distinguish exploitation from user error."
 portability_notes:
 - platform: "Splunk"
 note: "Use standard web access log fields (cs-uri-stem, sc-status)."
 suggested_owner: "Detection Engineering"
