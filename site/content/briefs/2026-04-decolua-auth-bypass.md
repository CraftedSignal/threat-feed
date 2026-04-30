---
title: Decolua 9router Authorization Bypass Vulnerability (CVE-2026-5842)
slug: 2026-04-decolua-auth-bypass
description: CVE-2026-5842 is an authorization bypass vulnerability in decolua 9router versions up to 0.3.47, allowing remote attackers to gain unauthorized access via manipulation of the /api endpoint.
date: "2026-04-09T05:16:06Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - authorization-bypass
  - router
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5842
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5842
  - https://github.com/decolua/9router/
  - https://github.com/decolua/9router/releases/tag/v0.3.75
rules:
  - title: Detect Access to Decolua 9router API Endpoint
    description: Detects access to the Decolua 9router administrative API endpoint, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Upgrade of Decolua 9router
    description: Detects access to the Decolua 9router upgrade endpoint, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-5842, affects decolua 9router versions up to 0.3.47. The vulnerability resides within an unknown function of the `/api` endpoint, specifically the Administrative API. Successful exploitation of this flaw allows a remote attacker to bypass authorization controls, potentially gaining administrative privileges. A public exploit for this vulnerability has been disclosed, increasing the risk of exploitation. Organizations using vulnerable versions of decolua 9router should upgrade to version 0.3.75 as soon as possible to mitigate the risk. This vulnerability was published on April 9, 2026 and poses a significant threat due to the availability of a public exploit.

## Attack Chain

1.  Attacker identifies a vulnerable decolua 9router instance running a version prior to 0.3.75.
2.  The attacker sends a crafted HTTP request to the `/api` endpoint.
3.  The crafted request exploits the authorization bypass vulnerability in the targeted function.
4.  The vulnerable application fails to properly validate the attacker's authorization, granting them access.
5.  The attacker gains unauthorized access to administrative functionalities.
6.  The attacker leverages the unauthorized access to modify router configurations.
7.  The attacker can then potentially perform actions like changing DNS settings, creating rogue user accounts, or disrupting network services.

## Impact

Successful exploitation of CVE-2026-5842 allows attackers to bypass authorization and gain unauthorized administrative access to the decolua 9router. This can lead to complete compromise of the router, allowing attackers to eavesdrop on network traffic, redirect traffic to malicious sites, or disrupt network services. Given the availability of a public exploit, vulnerable routers are at high risk of compromise. This vulnerability can have severe consequences for both home and business networks relying on decolua 9router.

## Recommendation

*   Upgrade all decolua 9router instances to version 0.3.75 or later to remediate CVE-2026-5842.
*   Monitor web server logs for suspicious activity targeting the `/api` endpoint using the Sigma rule provided below.
*   Implement firewall rules to restrict access to the administrative interface of the router.
*   Review and audit existing router configurations for any unauthorized changes after applying the provided Sigma rule to detect any potential intrusions.
