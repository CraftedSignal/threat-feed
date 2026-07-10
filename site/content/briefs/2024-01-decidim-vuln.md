---
title: Decidim Amendment Manipulation Vulnerability (CVE-2026-40869)
slug: 2024-01-decidim-vuln
description: CVE-2026-40869 allows authenticated users to manipulate amendments in Decidim versions 0.19.0 prior to 0.30.5 and 0.31.1, potentially hijacking authorship and impacting proposal integrity.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - decidim
  - vulnerability
  - amendment
  - manipulation
vendors:
  - Decidim
products:
  - Decidim
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40869
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40869
rules:
  - title: Detect Decidim Amendment Manipulation via HTTP POST
    description: Detects suspicious HTTP POST requests targeting amendment acceptance/rejection endpoints in Decidim, indicating potential exploitation of CVE-2026-40869.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Decidim Amendment Rejection via HTTP POST
    description: Detects suspicious HTTP POST requests targeting amendment rejection endpoints in Decidim, indicating potential exploitation of CVE-2026-40869.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Decidim is an open-source participatory democracy framework used by organizations to facilitate online discussions and decision-making. A vulnerability, CVE-2026-40869, affects Decidim versions 0.19.0 prior to 0.30.5 and 0.31.1. This flaw allows any registered and authenticated user to accept or reject amendments to proposals, even if they are not the original author. This can lead to unauthorized modification of proposals and the elevation of malicious users to co-authorship status, potentially undermining the integrity of the participatory process. The vulnerability was reported on 2026-04-21. Organizations using vulnerable versions of Decidim are at risk of having their proposals manipulated and their decision-making processes subverted.

## Attack Chain

1.  Attacker registers an account on the Decidim platform.
2.  Attacker authenticates to the Decidim platform using their registered credentials.
3.  Attacker identifies a proposal with the "amendments" feature enabled.
4.  Attacker views the available amendments for the target proposal through the web interface (HTTP GET request to view amendment details).
5.  Attacker crafts a malicious HTTP POST request to either accept or reject an amendment, bypassing intended authorization checks.
6.  The Decidim application incorrectly processes the attacker's request, allowing the attacker to modify the amendment's status.
7.  If the attacker accepts the amendment, they may be elevated to co-authorship of the original proposal.
8.  The altered amendment status is reflected on the Decidim platform, potentially influencing voting or decision-making processes.

## Impact

Successful exploitation of CVE-2026-40869 allows any registered user to manipulate amendments within Decidim proposals. This can lead to unauthorized modifications, data tampering, and the potential for a malicious actor to hijack the authorship of proposals. The number of affected organizations depends on the adoption rate of vulnerable Decidim versions. If successful, this can erode trust in the platform, manipulate democratic processes, and ultimately undermine the organization's decision-making capabilities.

## Recommendation

*   Upgrade Decidim to version 0.30.5 or 0.31.1 to patch CVE-2026-40869.
*   As a temporary workaround, disable amendment reactions for amendable components within Decidim, as recommended in the vulnerability description.
*   Monitor Decidim web server logs for suspicious POST requests to amendment endpoints originating from unusual IP addresses using the provided Sigma rule.
*   Implement the Sigma rule to detect unauthorized amendment modifications based on HTTP request parameters.
