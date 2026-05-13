---
title: Kyverno Vulnerability Allows Cross-Site Scripting
slug: 2026-05-kyverno-xss
description: A remote, authenticated attacker can exploit a vulnerability in Kyverno to perform a cross-site scripting attack.
date: "2026-05-13T09:31:18Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - xss
  - web-application
  - kyverno
products:
  - Kyverno
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1511
rules:
  - title: Detect Kyverno XSS Attempt via HTTP Request
    description: Detects potential XSS attempts against Kyverno based on common JavaScript injection patterns in HTTP requests.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Kyverno XSS Attempt via HTTP Body
    description: Detects potential XSS attempts against Kyverno based on common JavaScript injection patterns in HTTP request bodies.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists in Kyverno that allows for cross-site scripting (XSS) attacks. An authenticated, remote attacker can exploit this flaw to inject malicious scripts into the web application interface. This can lead to session hijacking, defacement of the web application, or the redirection of users to malicious websites. The exact version of Kyverno affected is not specified, but defenders should investigate and apply necessary patches or mitigations to prevent potential exploitation. The vulnerability poses a risk to the confidentiality and integrity of the Kyverno web interface.

## Attack Chain

1. The attacker authenticates to the Kyverno web interface using valid credentials.
2. The attacker identifies an input field or parameter within the web interface that is vulnerable to XSS. This could be a field that does not properly sanitize user-supplied input.
3. The attacker crafts a malicious payload containing JavaScript code.
4. The attacker injects the malicious payload into the vulnerable input field.
5. The Kyverno web application stores the malicious payload.
6. A user accesses a page or feature that displays the stored payload.
7. The user's web browser executes the malicious JavaScript code.
8. The attacker can then perform actions such as stealing cookies, redirecting the user, or defacing the web application.

## Impact

Successful exploitation of the XSS vulnerability in Kyverno can lead to various impacts, including unauthorized access to user accounts, theft of sensitive information (such as credentials or API keys), defacement of the Kyverno web interface, and redirection of users to phishing websites. This could potentially compromise the entire Kubernetes cluster managed by Kyverno.

## Recommendation

- Implement input validation and output encoding on all user-supplied data within the Kyverno web interface to prevent XSS attacks.
- Review the Kyverno source code to identify and remediate any potential XSS vulnerabilities.
- Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
