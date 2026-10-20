---
title: Remote Backdoor Vulnerability in Netis EAP930
slug: 2026-10-netis-eap930-backdoor
description: A vulnerability in the Netis EAP930 CGI endpoint allows remote attackers to trigger a backdoor via crafted manipulation of the SIGNATURE argument in the /cgi-bin/debug file.
date: "2026-10-20T00:30:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:netis:eap930:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-infrastructure
vendors:
  - Netis
products:
  - EAP930 (1.250905.115454)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument SIGNATURE leads to backdoor.
    confidence_band: high
cves:
  - id: CVE-2026-112360
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112360
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external access to EAP930 CGI endpoints
      owner: IT Operations
      due: 24h
      evidence: Vulnerability resides in the /cgi-bin/debug endpoint.
  mitigation_plan:
    - priority: medium_term
      action: Isolate vulnerable devices due to lack of vendor patch
      owner: IT Operations
      addresses: CVE-2026-112360
      evidence: Vendor was contacted early about this disclosure but did not respond in any way.
---

A security vulnerability (CVE-2026-112360) has been identified in the Netis EAP930 wireless access point, specifically within firmware version 1.250905.115454. The flaw exists within the return200 function of the /cgi-bin/debug CGI endpoint. Attackers can reach this endpoint remotely and manipulate the SIGNATURE argument to inject and execute a backdoor on the device. While the vulnerability requires a high degree of complexity to exploit successfully, it represents a significant risk to the integrity of affected network infrastructure. The vendor, Netis, was notified of this vulnerability prior to disclosure but did not provide a response or a patch, leaving devices currently running this firmware version in a vulnerable state.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to gain unauthorized access to the affected Netis EAP930 devices. By establishing a backdoor, attackers could potentially intercept network traffic, pivot into internal network segments, or maintain persistent access to the enterprise or residential environment. As the vulnerability is remote and the vendor has not provided a security update, all deployed EAP930 devices running version 1.250905.115454 are at risk of compromise.

## Recommendation

1. Inventory all instances of Netis EAP930 hardware within the environment to identify devices running firmware version 1.250905.115454.
2. Restrict network access to the management interface and CGI endpoints of all Netis EAP930 devices to known, trusted management subnets via firewall rules.
3. Given the lack of a vendor patch, consider isolating affected devices from the internal network until a secure firmware version is released or compensating controls are implemented.
4. Monitor web server and firewall logs for unusual POST or GET requests targeting the /cgi-bin/debug endpoint with non-standard values in the SIGNATURE parameter.
