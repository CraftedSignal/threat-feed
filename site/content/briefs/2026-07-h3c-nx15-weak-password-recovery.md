---
title: H3C NX15 Weak Password Recovery Vulnerability (CVE-2026-15479)
slug: 2026-07-h3c-nx15-weak-password-recovery
description: A critical vulnerability, CVE-2026-15479, in H3C NX15 V100R017 allows remote attackers to perform weak password recovery by manipulating the 'newPass' argument in the '/api/login/modify' endpoint, leading to unauthorized administrator access.
date: "2026-07-12T06:19:38Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - vulnerability
  - api-exploitation
  - password-reset
  - network-device
  - remote-access
vendors:
  - H3C
products:
  - NX15 V100R017
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was found in H3C NX15 V100R017... The attack may be launched remotely. The exploit has been made public and could be used.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The manipulation of the argument newPass results in weak password recovery.
    confidence_band: high
cves:
  - id: CVE-2026-15479
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15479
  - https://github.com/coconut652-7/IOT_Vul_Public/tree/main/H3C/NX15R017/pre_auth_pwd_change
  - https://vuldb.com/cve/CVE-2026-15479
  - https://vuldb.com/submit/837069
  - https://vuldb.com/vuln/377785
  - https://vuldb.com/vuln/377785/cti
iocs:
  - type: url
    value: https://github.com/coconut652-7/IOT_Vul_Public/tree/main/H3C/NX15R017/pre_auth_pwd_change
  - type: url
    value: https://vuldb.com/cve/CVE-2026-15479
  - type: url
    value: https://vuldb.com/submit/837069
  - type: url
    value: https://vuldb.com/vuln/377785
  - type: url
    value: https://vuldb.com/vuln/377785/cti
ioc_counts:
  url: 5
---

A critical vulnerability, CVE-2026-15479, has been identified in H3C NX15 V100R017 devices, specifically within the Administrator Password Modification Endpoint. The flaw resides in the `change_passwd` function of the `/api/login/modify` file. By manipulating the `newPass` argument during a password change request, an unauthenticated remote attacker can exploit a weak password recovery mechanism. This allows the attacker to reset the administrator password, gaining unauthorized access to the device. The exploit for this vulnerability has been made public, indicating a heightened risk of exploitation in the wild. Organizations using affected H3C NX15 devices should immediately apply vendor-provided patches or mitigations to prevent potential compromise and ensure the integrity of their network infrastructure.

## Attack Chain

1. **Vulnerability Discovery:** An attacker identifies vulnerable H3C NX15 V100R017 devices exposed on the internet or within an accessible network segment.
2. **API Endpoint Identification:** The attacker targets the `/api/login/modify` endpoint, specifically the `change_passwd` function, which handles administrator password modifications.
3. **Argument Manipulation:** The attacker crafts a malicious HTTP request to the `/api/login/modify` endpoint, manipulating the `newPass` argument in a way that triggers the weak password recovery vulnerability. The specific manipulation details are part of the public exploit.
4. **Password Reset Execution:** The vulnerable H3C device processes the crafted request, failing to properly validate the password change operation. This results in the administrator password being reset to an attacker-controlled value or a known weak default.
5. **Unauthorized Access:** The attacker uses the newly set or recovered administrator password to log into the H3C NX15 device.
6. **Device Compromise:** With administrative access, the attacker can then modify device configurations, exfiltrate sensitive network information, disrupt network operations, or establish persistence within the network.

## Impact

Successful exploitation of CVE-2026-15479 allows a remote attacker to gain full administrative control over the affected H3C NX15 V100R017 device. This leads to complete compromise of the device, enabling unauthorized configuration changes, potential network segmentation bypasses, data exfiltration from devices connected to the router, and disruption of network services. Given that this is a network device, the impact can extend to the entire network infrastructure managed by the device, potentially affecting all connected clients and servers. The public availability of an exploit significantly increases the risk of widespread attacks targeting unpatched systems.

## Recommendation

* Patch CVE-2026-15479 on all H3C NX15 V100R017 devices immediately once a vendor patch is released to mitigate the weak password recovery vulnerability.
* Monitor web server logs for suspicious requests to `/api/login/modify` on affected H3C NX15 devices that may indicate attempted exploitation.
* Review access logs and administrator accounts on H3C NX15 devices for any unauthorized password changes or logins following the detection of suspicious activity.
