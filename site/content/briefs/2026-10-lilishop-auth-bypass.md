---
title: Improper Authorization Vulnerability in PickMall Lilishop
slug: 2026-10-lilishop-auth-bypass
description: PickMall Lilishop up to version 4.2.4 contains an improper authorization vulnerability in the Mobile Binding component, allowing remote attackers to manipulate the Username argument to bypass authorization controls.
date: "2026-10-06T02:52:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:pickmall:lilishop:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - auth-bypass
vendors:
  - PickMall
products:
  - Lilishop (<= 4.2.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This manipulation of the argument Username causes improper authorization.
    confidence_band: high
cves:
  - id: CVE-2026-105571
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105571
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review web access logs for requests to /buyer/passport/member/bindMobile to identify potential exploitation attempts
      owner: SOC
      due: 24h
      evidence: Source document identifies /buyer/passport/member/bindMobile as the vulnerable path.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF to inspect or block unauthorized requests to the /buyer/passport/member/bindMobile endpoint
      owner: IT Operations
      addresses: CVE-2026-105571
      evidence: NVD vulnerability disclosure indicates remote exploitability.
  gaps:
    - No vendor-provided fix/patch version exists.
---

A security vulnerability (CVE-2026-105571) exists in the PickMall Lilishop e-commerce platform, affecting all versions up to and including 4.2.4. The flaw resides within the Mobile Binding component, specifically triggered through the /buyer/passport/member/bindMobile endpoint. By manipulating the Username argument, an unauthenticated or unauthorized remote attacker can successfully bypass intended authorization checks. The vulnerability has been publicly disclosed and a proof-of-concept exploit exists, increasing the risk of unauthorized account manipulation or account takeover. The project maintainers were notified of the issue but have not yet provided a resolution or patch. Defenders should treat this as a high-priority risk for internet-facing Lilishop instances, as the exploit is remote and does not require pre-existing authentication.

## Impact

The vulnerability allows unauthorized manipulation of member mobile bindings within the Lilishop platform. Successful exploitation grants an attacker the ability to associate arbitrary mobile numbers with existing accounts or potentially hijack access to accounts, resulting in full account compromise. Given the platform's role in e-commerce, this could lead to the unauthorized access of sensitive user data, fraudulent transactions, or significant disruption to business operations for organizations relying on this software.

## Recommendation

* Monitor web server logs for HTTP requests directed to the /buyer/passport/member/bindMobile endpoint.
* Implement stricter input validation or temporary blocking of the affected endpoint at the Web Application Firewall (WAF) level if not business-critical.
* Since no patch is currently available, perform continuous monitoring of user account binding activity for anomalous or unauthorized changes.
