---
title: Credential Access via Chromium Remote Debugging
slug: 2026-09-chromium-debugging-cookie-theft
description: Adversaries can exploit Chromium-based browser remote debugging features to extract authentication cookies and hijack active web sessions.
date: "2026-09-19T13:09:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - information-stealer
  - browser-security
vendors:
  - Google
  - Microsoft
products:
  - Chrome
  - Edge
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: Adversaries may steal web application or service session cookies and use them to gain access web applications or Internet services as an authenticated user without needing credentials.
    confidence_band: high
rules:
  - title: Detect Potential Cookie Theft via Chromium Remote Debugging
    description: Detects the execution of Chromium-based browsers with debugging process arguments, which may indicate an attempt to steal authentication cookies.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to environment.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line arguments used for malicious debugging.
  hunt_leads:
    - lead: Search for historical process creation logs containing --remote-debugging-port.
      technique_id: T1539
      data_needed:
        - Process command line logging
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source highlights remote debugging as a vector for cookie theft.
  mitigation_plan:
    - priority: medium_term
      action: Enforce security policies to restrict browser debugging arguments via Group Policy or EDR configurations.
      owner: IT Operations
      addresses: T1539
      evidence: Documentation suggests restricting remote debugging in production.
---

Adversaries may attempt to steal web session cookies by launching Chromium-based browsers with remote debugging arguments. This technique leverages legitimate browser functionality - specifically the remote debugging port - to allow an external actor to attach to a running browser instance, inspect its contents, and extract sensitive authentication cookies. By capturing these cookies, an attacker can impersonate a user, gaining access to web applications and services without requiring the original credentials or bypassing multi-factor authentication. 

This activity is frequently associated with information-stealing malware and manual post-exploitation tasks. While Chromium-based browsers provide these debugging ports for legitimate development and testing, their misuse in a production or end-user environment is highly suspicious. Defenders should monitor for processes such as Google Chrome and Microsoft Edge being executed with specific debugging flags, particularly when paired with a custom user data directory argument, which allows the attacker to isolate the target browser instance.

## Impact

Successful exploitation allows attackers to bypass primary authentication and MFA, leading to full session hijacking of web applications. This results in unauthorized access to sensitive corporate data, SaaS platforms, and internal services, potentially leading to data exfiltration, service manipulation, or further persistence within the target environment.

## Recommendation

* Deploy the Sigma rules provided below to detect browsers launched with debugging arguments in non-development environments.
* Implement endpoint security policies to block or alert on the use of remote debugging arguments (`--remote-debugging-port`, `--remote-debugging-pipe`) for standard user accounts.
* If a positive match is found, isolate the affected host and immediately invalidate all active web sessions for the user account associated with the process to mitigate the impact of potentially stolen cookies.
* Conduct a review of account logs to identify unauthorized logins to web services originating from anomalous IP addresses or sessions immediately following the detected process execution.
