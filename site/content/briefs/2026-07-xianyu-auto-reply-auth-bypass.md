---
title: Zhinianboke Xianyu-Auto-Reply Missing Authorization Vulnerability (CVE-2026-15752)
slug: 2026-07-xianyu-auto-reply-auth-bypass
description: A missing authorization vulnerability (CVE-2026-15752) exists in the /api/v1/users/ endpoint of zhinianboke xianyu-auto-reply, affecting versions up to commit dcb445ad97816ad65299a7580ee0c8c8f929da84, allowing a remote attacker to bypass authentication or authorization checks. An exploit for this vulnerability has been made public, and organizations using this product should apply the patch named 19fc3282a1bb78a05c34945c088525d20e081cbd to mitigate the risk.
date: "2026-07-14T23:19:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authorization-bypass
  - cve
  - web-vulnerability
  - network
vendors:
  - zhinianboke
products:
  - xianyu-auto-reply (up to dcb445ad97816ad65299a7580ee0c8c8f929da84)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was found in zhinianboke xianyu-auto-reply... Affected is an unknown function of the file /api/v1/users/ of the component Backend User Endpoint. Performing a manipulation results in missing authorization. The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-15752
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15752
---

A significant authorization vulnerability, identified as CVE-2026-15752, has been discovered in zhinianboke xianyu-auto-reply, specifically affecting versions up to commit `dcb445ad97816ad65299a7580ee0c8c8f929da84`. This flaw exists within an unspecified function of the `/api/v1/users/` endpoint, a crucial component of the Backend User Endpoint. The vulnerability permits a remote attacker to perform manipulations that bypass authorization checks, potentially leading to unauthorized access or actions. Although the product utilizes a rolling release model, making specific version information challenging to track, an exploit for this vulnerability has been publicly disclosed. Defenders must apply the provided patch, `19fc3282a1bb78a05c34945c088525d20e081cbd`, to address this critical security flaw and prevent potential compromise.

## Attack Chain

1. An attacker identifies a target system running the vulnerable zhinianboke xianyu-auto-reply application.
2. The attacker crafts a specialized HTTP request targeting the `/api/v1/users/` endpoint of the application.
3. The crafted request leverages an unspecified manipulation within this endpoint to bypass the standard authorization mechanisms.
4. Upon successful manipulation, the attacker gains unauthorized access or executes unauthorized actions within the application due to the missing authorization vulnerability.

## Impact

Successful exploitation of CVE-2026-15752 could lead to a range of severe consequences, including unauthorized access to user data, manipulation of application settings, or complete system compromise, depending on the privileges that can be bypassed. While the specific impact of the "missing authorization" is not detailed, such vulnerabilities typically allow attackers to perform actions reserved for authenticated or privileged users. The public availability of an exploit increases the urgency of remediation, as it lowers the barrier for attackers to leverage this flaw.

## Recommendation

* Apply the patch `19fc3282a1bb78a05c34945c088525d20e081cbd` to all instances of zhinianboke xianyu-auto-reply immediately to mitigate CVE-2026-15752.
* Monitor web server access logs for any unusual or unauthenticated requests to the `/api/v1/users/` endpoint.
