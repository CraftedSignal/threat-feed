---
title: OpenClaw SSRF Policy Bypass Vulnerability (CVE-2026-41912)
slug: 2026-04-openclaw-ssrf
description: OpenClaw before 2026.4.8 is vulnerable to server-side request forgery (SSRF) due to a policy bypass that allows attackers to trigger navigations past normal SSRF checks, potentially leading to unauthorized access of restricted resources.
date: "2026-04-28T19:37:44Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - cve-2026-41912
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41912
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41912
  - https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-vr5g-mmx7-h897
  - https://www.vulncheck.com/advisories/openclaw-server-side-request-forgery-policy-bypass-via-interaction-triggered-navigation
rules:
  - title: Detect OpenClaw SSRF Attempt via Suspicious Navigation
    description: Detects potential SSRF attempts in OpenClaw by monitoring for suspicious navigation patterns indicative of SSRF bypasses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw SSRF Attempt via Internal Resource Access
    description: Detects potential SSRF attempts in OpenClaw by monitoring for access to known internal resources.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.4.8 are susceptible to a server-side request forgery (SSRF) policy bypass vulnerability, identified as CVE-2026-41912. This flaw allows attackers to circumvent standard SSRF protections by manipulating browser interactions to trigger navigations. By exploiting this vulnerability, an attacker can potentially gain unauthorized access to internal resources and sensitive information that should otherwise be protected by SSRF mitigation measures. The vulnerability was reported on April 28, 2026, and poses a significant risk to organizations using affected versions of OpenClaw, as it can lead to the exposure of internal services and data.

## Attack Chain

1.  An attacker identifies an OpenClaw instance running a version prior to 2026.4.8.
2.  The attacker crafts a malicious request designed to exploit the SSRF policy bypass.
3.  The victim user, with access to the OpenClaw application, interacts with the attacker's crafted payload within their browser.
4.  The malicious request triggers a navigation event within the browser, bypassing the intended SSRF protections.
5.  OpenClaw, due to the policy bypass, processes the request without proper validation.
6.  The application makes an unintended request to an internal resource based on the attacker-controlled navigation.
7.  Sensitive information from the internal resource is accessed by the OpenClaw application.
8.  The attacker retrieves the data, completing the SSRF attack.

## Impact

Successful exploitation of CVE-2026-41912 can lead to the exposure of sensitive internal resources and data. An attacker could potentially access internal APIs, databases, or other services that are not intended to be exposed to the public internet. The impact depends on the nature of the resources exposed but could range from information disclosure to the compromise of internal systems.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.8 or later to remediate the SSRF vulnerability (CVE-2026-41912).
*   Deploy the provided Sigma rule to detect exploitation attempts by monitoring for suspicious navigation patterns indicative of SSRF bypass attempts.
