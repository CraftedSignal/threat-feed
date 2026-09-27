---
title: Host Header Injection in Sylius Password Reset Mechanism
slug: 2026-09-sylius-password-reset-poisoning
description: Sylius versions before 1.12.25, 1.13.17, 1.14.20, 2.1.16, and 2.2.9 are vulnerable to a password reset poisoning attack, allowing unauthenticated attackers to hijack administrator accounts via Host header manipulation.
date: "2026-09-27T15:07:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sylius:sylius:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - account-takeover
vendors:
  - Sylius
products:
  - Sylius (< 1.12.25, < 1.13.17, < 1.14.20, < 2.1.16, < 2.2.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An unauthenticated attacker can manipulate the Host header in a password reset request to redirect tokens to an external, attacker-controlled domain.
    confidence_band: high
cves:
  - id: CVE-2026-100870
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100870
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Sylius to versions 1.12.25, 1.13.17, 1.14.20, 2.1.16, 2.2.9 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies these fixed versions.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF/Load Balancer to reject requests with 'Host' headers not matching the legitimate domain
      owner: Security Operations
      addresses: CVE-2026-100870
      evidence: Mitigates Host header poisoning attempt.
---

Sylius versions released prior to 1.12.25, 1.13.17, 1.14.20, 2.1.16, and 2.2.9 contain a critical vulnerability in the password reset workflow. The application incorrectly utilizes the HTTP 'Host' header provided in an incoming password reset request to construct the password reset link sent to the user. An unauthenticated attacker can exploit this by injecting a malicious domain into the 'Host' header while initiating a reset request for a target administrator's email address. The resulting reset email contains a link pointing to an attacker-controlled server, facilitating the theft of the reset token and leading to full account takeover. This vulnerability poses a significant risk to administrative access and underscores the necessity of validating input derived from HTTP headers against an allowlist of expected domains.

## Attack Chain

1. Attacker identifies a target administrator's email address associated with the Sylius instance.
2. Attacker initiates a password reset request via the legitimate application endpoint (e.g., /password-reset/request).
3. Attacker intercepts the outgoing HTTP request using a proxy or intercepting tool.
4. Attacker modifies the 'Host' header field in the request to point to an attacker-controlled domain.
5. The Sylius backend processes the request and uses the malicious 'Host' header to generate the URL for the password reset token.
6. The application sends the password reset email to the legitimate administrator, containing the poisoned, attacker-controlled link.
7. The administrator clicks the malicious link, sending the reset token to the attacker's infrastructure.
8. Attacker utilizes the intercepted token to reset the administrator's password and gain unauthorized administrative access.

## Impact

Successful exploitation allows unauthenticated attackers to perform full account takeover of administrative accounts. This grants attackers unauthorized access to the Sylius management dashboard, allowing for data exfiltration, system configuration changes, and further persistence within the application environment.

## Recommendation

Prioritize patching affected Sylius installations to the latest secure versions. For environments unable to patch immediately, implement strict validation of the 'Host' header at the web application firewall (WAF) or load balancer level to ensure only authorized hostnames are accepted for administrative requests.
