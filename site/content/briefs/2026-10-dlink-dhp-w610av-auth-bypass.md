---
brief_id: brief-2026-10-21-dlink-dhp-w610av-auth-bypass
event_id: brief-2026-10-21-dlink-dhp-w610av-auth-bypass
revision: 1
activity_at: "2026-10-21T02:15:08Z"
title: 'D-Link DHP-W610AV: HNAP login configuration vulnerability (CVE-2026-113736)'
slug: 2026-10-dlink-dhp-w610av-auth-bypass
description: A critical vulnerability in D-Link DHP-W610AV allows remote attackers to force an empty password configuration via the HNAP Login interface, enabling unauthorized access.
date: "2026-10-21T02:15:08Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source information is sufficient; no environment validation performed.
cpes:
  - cpe:2.3:h:dlink:dhp-w610av:1.02eub03:*:*:*:*:*:*:*
tags:
  - cve-2026-113736
  - vulnerability
  - network-infrastructure
vendors:
  - D-Link
products:
  - DHP-W610AV (1.02EUb03)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-113736
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113736
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external access to HNAP interfaces for D-Link DHP-W610AV devices
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows remote unauthenticated access
  mitigation_plan:
    - priority: immediate
      action: Apply firmware patch for CVE-2026-113736 if provided by vendor
      owner: IT Operations
      addresses: CVE-2026-113736
      evidence: Vulnerability in firmware 1.02EUb03
---

D-Link DHP-W610AV firmware version 1.02EUb03 contains a critical security vulnerability (CVE-2026-113736) within the HNAP (Home Network Administration Protocol) Login component. The issue exists in the 'login_prepare_hnap' function, located within the 'etc/defnodes/defaultvalue.xml' file. An unauthenticated remote attacker can exploit this vulnerability by manipulating the 'Password' argument during the HNAP authentication process. Successful exploitation results in the device configuration being modified to set an empty administrative password. This flaw, which carries a CVSS v3.1 base score of 9.8, provides a straightforward path for attackers to gain unauthorized administrative access to affected network devices. Public disclosure of the exploit increases the likelihood of opportunistic exploitation in the wild.

## Attack Chain

1. The attacker performs network reconnaissance to identify exposed HNAP interfaces on D-Link DHP-W610AV devices.
2. The attacker targets the HNAP service, typically accessible via HTTP/TCP ports often associated with device management.
3. The attacker crafts a malicious HTTP POST request targeting the HNAP login interface.
4. The request includes a manipulated 'Password' argument as defined in the 'login_prepare_hnap' function.
5. The device's HNAP service processes the malformed input without proper sanitization.
6. The vulnerability forces the device to overwrite the existing administrative configuration with an empty password.
7. The attacker authenticates to the device management interface using the now-empty administrative credentials.
8. The attacker achieves full administrative control over the network device for further exploitation or exfiltration.

## Impact

Successful exploitation allows remote, unauthenticated attackers to bypass authentication on D-Link DHP-W610AV devices. This leads to complete administrative takeover of the networking hardware, enabling the attacker to intercept traffic, modify network settings, or pivot deeper into the local network environment. Given the nature of the device, this could affect numerous residential or small-office environments where these powerline adapters are deployed.

## Recommendation

Prioritized, concrete actions for detection and mitigation:
* Restrict access to the HNAP interface of the D-Link DHP-W610AV to trusted internal IP ranges via firewall or ACLs.
* Disable remote management interfaces on the device if they are not strictly required for operation.
* Monitor network traffic for HTTP POST requests directed toward HNAP-related endpoints containing anomalous 'Password' parameter values.
* Check D-Link support resources for any firmware updates that remediate CVE-2026-113736 and apply them to all managed devices immediately.
