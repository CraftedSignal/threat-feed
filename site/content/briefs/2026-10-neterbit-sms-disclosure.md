---
title: Unauthenticated SMS Disclosure in Neterbit NW-431F
slug: 2026-10-neterbit-sms-disclosure
description: Neterbit NW-431F LTE routers are vulnerable to unauthenticated information disclosure via the /sms.json endpoint, allowing attackers to retrieve SMS messages including potential one-time passcodes.
date: "2026-10-15T18:03:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:neterbit:nw-431f:*:*:*:*:*:*:*:*
tags:
  - information-disclosure
  - router
  - lte
  - cve-2026-108578
vendors:
  - Neterbit
products:
  - NW-431F (firmware 20250715)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Unauthenticated SMS disclosure in Neterbit NW-431F via the /sms.json endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-108578
    cvss: 5.3
    epss: 0.00485
references:
  - https://sploitus.com/exploit?id=87C4188B-6CE2-5757-A5DC-F463DDA3A519
  - https://vulners.com/cve/CVE-2026-108578
  - https://vuldb.com/vuln/416235
rules:
  - title: Detect Unauthenticated Access to Neterbit SMS Endpoint
    description: Detects unauthorized GET requests to the /sms.json endpoint on Neterbit routers, which is indicative of information disclosure attempts for CVE-2026-108578.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review perimeter firewall logs for inbound access to Neterbit router management interfaces.
      owner: SOC
      due: 24h
      evidence: The vector is AV:N (Network) which requires no local access.
  mitigation_plan:
    - priority: immediate
      action: Block public access to the Neterbit NW-431F web interface and the /sms.json endpoint specifically.
      owner: IT Operations
      addresses: CVE-2026-108578
      evidence: Remediation section of the source advisory.
---

The Neterbit NW-431F embedded LTE router, specifically running firmware version 20250715, contains an unauthenticated information disclosure vulnerability identified as CVE-2026-108578. The vulnerability resides in the `/sms.json` web endpoint, which returns stored SMS records, including sender numbers, timestamps, and message bodies, without requiring any authentication. Because these routers utilize SIM cards to facilitate cellular communication, the exposed SMS logs often contain sensitive information such as one-time passcodes (OTP) intended for multi-factor authentication or account recovery. The vulnerability was disclosed following an unsuccessful attempt to coordinate with the vendor. As of the time of reporting, no security patch is available to resolve the underlying access control issue.

## Impact

Successful exploitation allows remote, unauthenticated attackers to intercept SMS messages sent to the router's SIM card. This enables the theft of sensitive authentication tokens, such as OTPs, which may lead to account takeover or further compromise of services linked to the cellular number associated with the router. The vulnerability affects all Neterbit NW-431F devices running the specified firmware.

## Recommendation

1. Restrict access to the router's management web interface; do not expose the interface to the internet.
2. Implement an access control list (ACL) or reverse proxy rule to block all HTTP requests to the `/sms.json` endpoint.
3. Move the device management interface to a segmented management VLAN or require a VPN connection for administrative access.
4. If the SMS functionality is not required, consider replacing the device with hardware that allows for the secure disabling of such features.
5. Audit network traffic for unauthorized `GET /sms.json` requests to identify exploitation attempts against managed devices.
