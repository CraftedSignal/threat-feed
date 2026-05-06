---
title: Luanti 5 Improper Access Control Vulnerability (CVE-2026-40960)
slug: 2026-04-luanti-access
description: Luanti 5 before 5.15.2 allows unintended access to an insecure environment if a crafted mod intercepts requests when secure mods are enabled, potentially leading to unauthorized access and control.
date: "2026-04-16T01:16:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-40960
  - luanti
  - access-control
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40960
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40960
  - https://github.com/luanti-org/luanti/commit/0faf529bc4b89e70a275ed1162047815118f2413
  - https://github.com/luanti-org/luanti/commit/827fd4cf7f989482b2dad381fa4afd642ea73e8c
  - https://github.com/luanti-org/luanti/security/advisories/GHSA-22c4-238c-m5j4
rules:
  - title: Detect Suspicious HTTP Requests from Unusual Luanti Mods
    description: Detects potentially malicious HTTP requests originating from uncommon or newly deployed Luanti mods
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Luanti Mod Deployment
    description: Detects deployment of new Luanti modules, which should be monitored for suspicious activity related to CVE-2026-40960
    platform: sigma
    severity: informational
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Luanti 5, a software package (details not provided in source), prior to version 5.15.2, suffers from an improper access control vulnerability (CVE-2026-40960). This flaw can be exploited when at least one mod is configured as either `secure.trusted_mods` or `secure.http_mods`. Under these conditions, a specially crafted malicious mod can intercept requests intended for the insecure environment or HTTP API, effectively bypassing intended security controls. The vulnerability allows the malicious mod to gain unauthorized access to sensitive resources, potentially leading to data breaches or system compromise. Organizations using affected versions of Luanti 5 are urged to upgrade to version 5.15.2 or implement mitigating controls to prevent exploitation.

## Attack Chain

1. An attacker identifies a Luanti 5 instance running a version prior to 5.15.2 with at least one mod configured as `secure.trusted_mods` or `secure.http_mods`.
2. The attacker crafts a malicious mod designed to intercept HTTP requests.
3. The attacker deploys the crafted mod to the Luanti 5 environment.
4. The malicious mod intercepts requests directed towards the insecure environment or HTTP API.
5. Due to the vulnerability, the malicious mod gains unauthorized access to the targeted environment or API.
6. The attacker leverages the gained access to perform unauthorized actions, such as reading sensitive data or manipulating system configurations.
7. The attacker exfiltrates sensitive data or establishes persistent access for future malicious activities.

## Impact

Successful exploitation of CVE-2026-40960 can lead to complete compromise of the insecure environment or HTTP API within Luanti 5. This could result in unauthorized access to sensitive data, modification of system configurations, or complete system takeover. The severity of the impact depends on the specific functionality and data exposed by the insecure environment, but could include data breaches, financial loss, or reputational damage.

## Recommendation

*   Upgrade Luanti 5 to version 5.15.2 or later to patch CVE-2026-40960.
*   If upgrading is not immediately feasible, review the configuration of `secure.trusted_mods` and `secure.http_mods` and remove any untrusted or unnecessary mods.
*   Monitor Luanti 5 webserver logs for suspicious HTTP requests originating from unusual or newly deployed mods using the provided Sigma rule.
*   Implement strict access control policies for deploying and managing Luanti 5 mods to prevent unauthorized installation of malicious modules.
