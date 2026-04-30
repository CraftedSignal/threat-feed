---
title: OpenClaw Security Bypass Vulnerability Allows Persistent Browser Profile Mutation
slug: 2026-04-openclaw-bypass
description: OpenClaw before 2026.4.8 contains a security bypass vulnerability in node.invoke(browser.proxy) that allows attackers to circumvent the browser.request persistent profile-mutation guard and modify browser configurations.
date: "2026-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - security-bypass
  - browser-automation
  - profile-mutation
vendors:
  - openclaw
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
cves:
  - id: CVE-2026-42431
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42431
  - https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-cmfr-9m2r-xwhq
  - https://www.vulncheck.com/advisories/openclaw-persistent-profile-mutation-via-node-invoke-browser-proxy-bypass
rules:
  - title: Detect OpenClaw Persistent Profile Mutation via node.invoke(browser.proxy) Bypass
    description: Detects attempts to exploit CVE-2026-42431 by monitoring network connections for calls to node.invoke(browser.proxy) that may bypass profile mutation guards.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - network_connection
      - linux
  - title: Detect OpenClaw Process Tampering via Profile Mutation
    description: Detects potential process tampering by monitoring for unexpected modifications to OpenClaw's browser profile files.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw, a browser automation tool, is vulnerable to a security bypass (CVE-2026-42431) affecting versions prior to 2026.4.8. This vulnerability resides in the `node.invoke(browser.proxy)` function, which improperly allows mutation of persistent browser profiles. An attacker can leverage this flaw to bypass the `browser.request` persistent profile-mutation guard. Successful exploitation leads to unauthorized modification of browser configurations, potentially enabling malicious activities such as injecting malicious extensions, altering browser settings, or compromising user data. The vulnerability was publicly disclosed on April 28, 2026.

## Attack Chain

1.  Attacker identifies a vulnerable OpenClaw instance running a version prior to 2026.4.8.
2.  Attacker crafts a malicious script that calls the `node.invoke(browser.proxy)` function.
3.  The script is designed to bypass the `browser.request` persistent profile-mutation guard.
4.  The `node.invoke(browser.proxy)` function is exploited to mutate the persistent browser profile.
5.  The browser configuration is modified to include malicious settings, such as altered proxy settings or injected malicious extensions.
6.  OpenClaw uses the modified browser profile for subsequent browser automation tasks.
7.  The malicious configurations allow the attacker to intercept or modify browser traffic.
8.  The attacker gains unauthorized access to sensitive information or injects malicious content into the browser session.

## Impact

Successful exploitation of CVE-2026-42431 allows attackers to modify browser configurations, potentially leading to data theft, session hijacking, or the injection of malicious content. This can compromise user credentials, financial data, or other sensitive information handled by the browser. The vulnerability affects all users of OpenClaw versions prior to 2026.4.8. While the exact number of affected users is unknown, the impact is high due to the potential for widespread compromise of browser profiles and associated data.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.8 or later to patch CVE-2026-42431.
*   Monitor OpenClaw scripts for suspicious calls to `node.invoke(browser.proxy)` using network connection monitoring.
*   Implement strict access controls to limit who can modify OpenClaw scripts and browser profiles.
*   Deploy the Sigma rule provided below to detect attempts to bypass the `browser.request` persistent profile-mutation guard.
