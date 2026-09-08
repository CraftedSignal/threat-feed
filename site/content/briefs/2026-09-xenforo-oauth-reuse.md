---
title: XenForo OAuth2 Authorization Code Reuse Vulnerability
slug: 2026-09-xenforo-oauth-reuse
description: XenForo versions prior to 2.3.13 contain an OAuth2 authorization code reuse vulnerability (CVE-2026-73311) that allows attackers to obtain unauthorized token pairs by submitting previously used codes.
date: "2026-09-08T15:41:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:xenforo:xenforo:*:*:*:*:*:*:*:*
tags:
  - web-application
  - vulnerability
  - authentication-bypass
vendors:
  - XenForo
products:
  - XenForo (< 2.3.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: XenForo before 2.3.13 contains an OAuth2 authorization code reuse vulnerability that allows attackers to obtain unauthorized token pairs by submitting a previously used authorization code.
    confidence_band: high
cves:
  - id: CVE-2026-73311
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73311
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade XenForo to version 2.3.13 or later
      owner: IT Operations
      addresses: CVE-2026-73311
      evidence: XenForo before 2.3.13 contains an OAuth2 authorization code reuse vulnerability
---

XenForo software versions prior to 2.3.13 contain a critical vulnerability in the handling of OAuth2 authorization codes, tracked as CVE-2026-73311. The application fails to properly invalidate or mark authorization codes as consumed after the initial token issuance. This oversight allows an attacker to replay a previously used authorization code to the token endpoint, bypassing the mandatory single-use security guarantee required by the OAuth2 specification. By successfully re-submitting the code, the attacker can receive an independent, unauthorized token pair for the same user and associated scopes. This vulnerability represents a significant risk to user account integrity and session security, as it facilitates unauthorized access to account data and privileges without requiring further interaction from the target user. Defenders should prioritize updating to version 2.3.13 or later to ensure compliance with OAuth2 security standards.

## Impact

Successful exploitation allows attackers to gain unauthorized access to user accounts, potentially leading to full account takeover or unauthorized data exfiltration depending on the scopes associated with the leaked token. The vulnerability affects any XenForo environment utilizing the OAuth2 authorization code flow.

## Recommendation

* Upgrade all XenForo instances to version 2.3.13 or later immediately to address the underlying authorization code validation logic (CVE-2026-73311).
* Review OAuth2 token usage logs to identify instances of duplicate authorization code submission.
