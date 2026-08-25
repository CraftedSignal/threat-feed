---
title: 'CVE-2026-72700: Timing Vulnerability in Grav Login Plugin'
slug: 2026-08-grav-plugin-timing-vuln
description: The Grav login plugin for Composer is vulnerable to token-recovery via timing attacks due to non-constant-time string comparisons and a lack of rate limiting on password reset endpoints.
date: "2026-08-25T06:05:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - vulnerability
  - web-application
vendors:
  - getgrav
products:
  - grav-plugin-login
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The grav-plugin-login plugin for Grav is vulnerable to a timing attack due to the use of non-constant-time string comparisons during password reset and account activation token verification.
    confidence_band: high
cves:
  - id: CVE-2026-72700
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72700
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade grav-plugin-login to 3.9.1
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-72700 remediation
  mitigation_plan:
    - priority: immediate
      action: Configure WAF rate limiting for /taskReset and activation paths
      owner: IT Operations
      addresses: CVE-2026-72700
      evidence: Source notes lack of rate limiting
---

The getgrav/grav-plugin-login Composer plugin, versions prior to 3.9.1, contains a vulnerability that allows for potential account takeover via timing analysis. The issue resides in the classes/Controller.php and login.php files, where password reset and account activation tokens are validated using a non-constant-time '===' operator instead of the secure hash_equals() function. This allows an attacker to measure the time taken for the server to process token verification requests. Combined with the absence of rate limiting on the 'taskReset' endpoint, an attacker can theoretically brute-force valid tokens by analyzing response time variations. While no end-to-end network exploit has been observed, the design flaw represents a significant risk for administrative account compromise within impacted Grav deployments.

## Impact

Successful exploitation could lead to unauthorized account activation or password resets, potentially resulting in full administrative compromise of the affected Grav instance. This impacts all deployments utilizing the vulnerable plugin versions, particularly those exposed to the public internet where brute-force attempts can be performed systematically.

## Recommendation

- Upgrade the Grav login plugin to version 3.9.1 or later to remediate CVE-2026-72700.
- Implement request rate limiting at the WAF or reverse proxy level for all 'taskReset' and account activation endpoints to mitigate potential brute-force attempts.
- Audit web server access logs for anomalous spikes in traffic targeting password reset endpoints, which may indicate automated token-guessing attempts.
