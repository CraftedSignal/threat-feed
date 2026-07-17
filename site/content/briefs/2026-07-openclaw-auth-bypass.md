---
title: OpenClaw Authorization Bypass Vulnerability CVE-2026-62218
slug: 2026-07-openclaw-auth-bypass
description: An authorization bypass vulnerability (CVE-2026-62218) in OpenClaw versions prior to 2026.5.27 allows lower-trust callers to bypass role-management checks within the `device.pair.approve` feature, leading to privilege escalation and unauthorized actions.
date: "2026-07-17T02:28:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - application-vulnerability
vendors:
  - OpenClaw
products:
  - OpenClaw (before 2026.5.27)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: OpenClaw 2026.1.20 before 2026.5.27 contain an authorization bypass vulnerability in the device.pair.approve feature that allows lower-trust callers to bypass role-management checks. Attackers can perform actions requiring stronger authorization by reaching the affected feature through configured input paths.
    confidence_band: high
cves:
  - id: CVE-2026-62218
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62218
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-8v95-qqcm-qp9h
  - https://www.vulncheck.com/advisories/openclaw-authorization-bypass-via-device-pair-approve
---

CVE-2026-62218 describes a critical authorization bypass vulnerability affecting OpenClaw versions from 2026.1.20 up to, but not including, 2026.5.27. This flaw resides specifically within the `device.pair.approve` feature, which is intended to manage device pairing authorizations. The vulnerability permits callers with lower trust levels to circumvent established role-management checks. This means that an attacker, even with limited privileges within the OpenClaw system, can exploit this oversight to perform actions that typically require higher authorization. The exploit allows unauthorized execution of privileged functions by manipulating input paths to the affected feature, posing a significant risk for privilege escalation and unauthorized system control. The vulnerability has a CVSS v3.1 base score of 8.8, indicating a high severity threat.

## Attack Chain

1. An attacker gains initial, low-privileged access to an affected OpenClaw system, potentially through compromised credentials or another vulnerability.
2. The attacker identifies the `device.pair.approve` feature as a potential target for privilege escalation due to its critical role in device management.
3. The attacker crafts a malicious request or API call to invoke the `device.pair.approve` feature, intending to perform an action requiring elevated privileges.
4. Due to the authorization bypass flaw (CVE-2026-62218), the OpenClaw system fails to properly validate the attacker's low-trust authorization level against the required permissions for the requested action.
5. The system proceeds to execute the intended privileged action through the `device.pair.approve` feature, believing the request to be legitimate despite the caller's insufficient rights.
6. The attacker successfully performs an unauthorized, highly privileged action, effectively escalating their privileges within the OpenClaw environment.

## Impact

Successful exploitation of CVE-2026-62218 allows an attacker to achieve privilege escalation within the affected OpenClaw system. This means individuals with otherwise limited permissions can execute administrative functions or other actions requiring higher authorization, potentially leading to full system compromise. The impact includes unauthorized configuration changes, device pairing without proper approval, data manipulation, or potentially broader control over the system's operations and connected devices. The specific damage depends on the critical functions managed by the `device.pair.approve` feature and the attacker's objectives.

## Recommendation

* Patch affected OpenClaw instances immediately to version 2026.5.27 or later to address CVE-2026-62218.
* Review application logs for unusual or unauthorized calls to the `device.pair.approve` feature, especially from lower-privileged accounts.
