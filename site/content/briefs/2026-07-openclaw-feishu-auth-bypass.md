---
title: OpenClaw Feishu Tools Authorization Bypass Vulnerability (CVE-2026-62187)
slug: 2026-07-openclaw-feishu-auth-bypass
description: OpenClaw Feishu tools (npm package @openclaw/feishu) versions up to and including 2026.6.6 contain CVE-2026-62187, an authorization bypass vulnerability that allows lower-trust callers to perform unauthorized operations by ignoring per-account disablement or policy checks, leading to potential data manipulation or information disclosure.
date: "2026-07-13T22:23:52Z"
lastmod: "2026-07-13T22:24:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - npm-package
  - software-supply-chain
  - vulnerability
  - cve
vendors:
  - OpenClaw
products:
  - '@openclaw/feishu <= 2026.6.6'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A lower-trust caller or a configured input path could perform actions that should have required a stronger authorization or policy check, resulting in unauthorized operations.
    confidence_band: med
cves:
  - id: CVE-2026-62187
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62187
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-2q7j-2vhx-56g8
  - https://www.vulncheck.com/advisories/openclaw-feishu-tools-authorization-bypass
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62188
updates:
  - at: "2026-07-13T22:24:38Z"
    level: L2
    summary: 'merged source coverage: OpenClaw Feishu Permission Tools Incorrect Authorization Vulnerability'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62188
---

A critical authorization bypass vulnerability, identified as CVE-2026-62187, affects OpenClaw Feishu tools (npm package `@openclaw/feishu`) in all versions up to and including 2026.6.6. This flaw allows a lower-trust caller or input path to circumvent per-account disablement and other authorization checks, enabling them to perform operations that should require stronger authentication or policy enforcement. The vulnerability, first published on July 13, 2026, by VulnCheck and tracked by NVD, poses a significant risk to applications integrating this npm package, potentially leading to unauthorized data modification, access to sensitive information, or execution of restricted functions. The actual impact depends on the specific configuration of the operator and the accessibility of the affected feature to lower-trust input.

## Attack Chain

1. An attacker conducts reconnaissance to identify applications or services that incorporate the vulnerable `@openclaw/feishu` npm package, specifically targeting versions `<= 2026.6.6`.
2. The attacker analyzes the application's configuration and the library's exposed functionalities to pinpoint "lower-trust caller" interaction points or "configured input paths" that utilize the vulnerable component.
3. A malicious input or API request is crafted, designed to interact with the `@openclaw/feishu` library's functions responsible for authorization, particularly those related to account disablement.
4. The crafted input is submitted to the vulnerable application, which then passes it to the `@openclaw/feishu` library.
5. Due to CVE-2026-62187, the library improperly processes the input, ignoring per-account disablement settings or failing to enforce stronger authorization/policy checks.
6. The application, under the influence of the bypassed authorization, executes unauthorized operations such as modifying data, accessing restricted resources, or triggering privileged functions.
7. The successful exploitation results in the attacker achieving their objective, which could include data manipulation, information disclosure, or service disruption within the compromised application.

## Impact

The successful exploitation of CVE-2026-62187 can lead to significant unauthorized operations within applications utilizing the `@openclaw/feishu` package. Depending on the application's functionality and the privileges granted to the vulnerable component, attackers could modify critical data, access sensitive user or system information, or perform actions typically reserved for administrators. The NVD assigns a CVSS v3.1 base score of 8.1 (High), indicating a severe risk. While no specific victim count or targeted sectors are available, any organization deploying applications with the vulnerable package is at risk of data integrity loss, confidentiality breaches, or disruption of services due to unauthorized activity.

## Recommendation

* Patch CVE-2026-62187 by upgrading the `@openclaw/feishu` npm package to version `2026.6.9` or later immediately.
* Review applications utilizing `@openclaw/feishu` for configurations that allow "lower-trust callers" or "configured input paths" to interact with sensitive functions, and implement additional layers of authorization.
* Monitor application logs for unusual activity originating from accounts that should be disabled or from callers with limited privileges, which could indicate exploitation of the authorization bypass vulnerability.
