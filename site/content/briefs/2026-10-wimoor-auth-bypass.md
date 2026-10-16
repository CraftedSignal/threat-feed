---
title: Authentication Bypass in WIMOOR via Unsigned X-USERINFO Header
slug: 2026-10-wimoor-auth-bypass
description: WIMOOR through commit ec86736 contains an authentication bypass vulnerability that allows unauthorized tenants to escalate privileges and access sensitive financial data by forging the unsigned X-USERINFO header.
date: "2026-10-16T18:50:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wimoor:wimoor:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-application
  - cloud
vendors:
  - WIMOOR
products:
  - WIMOOR (<= ec86736)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: By reaching the backend service ports directly, bypassing the gateway, an attacker can forge companyid and manager or admin usertype values.
    confidence_band: high
cves:
  - id: CVE-2026-111691
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111691
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Restrict network access to WIMOOR backend ports to authorized gateway IPs only
      owner: IT Operations
      due: 24h
      evidence: Source states exploitation occurs when reaching backend service ports directly, bypassing the gateway
  mitigation_plan:
    - priority: immediate
      action: Upgrade WIMOOR beyond commit ec86736
      owner: IT Operations
      addresses: CVE-2026-111691
      evidence: NVD vulnerability details
---

WIMOOR through commit ec86736 is susceptible to an authentication bypass vulnerability. The flaw exists because the application incorrectly processes the unsigned 'X-USERINFO' HTTP header when backend service ports are accessed directly, bypassing the intended gateway or proxy authentication mechanisms. By manipulating the 'companyid', 'manager', or 'admin' fields within this header, an unauthenticated attacker can successfully impersonate any tenant, including administrative accounts. This flaw allows unauthorized actors to read and modify sensitive internal information, including order histories, financial records, and Amazon seller authorizations. This represents a significant risk to organizations using WIMOOR, particularly if backend instances are reachable from untrusted network segments.

## Impact

Successful exploitation allows for full tenant impersonation and unauthorized access to sensitive business operations. Attackers can view or manipulate financial data, modify order processing, and compromise third-party integrations such as Amazon seller authorizations, potentially leading to significant financial loss and operational disruption for users of the platform.

## Recommendation

* Immediately restrict network access to WIMOOR backend service ports to ensure all traffic must traverse the authorized gateway, preventing direct access.
* Patch WIMOOR by updating to a version beyond commit ec86736, ensuring that the application validates the authenticity of 'X-USERINFO' headers instead of relying on client-provided data.
* Review web application firewall (WAF) logs for any incoming requests containing custom 'X-USERINFO' headers, which should be considered anomalous if originating from external or non-internal-gateway IP addresses.
