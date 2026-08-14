---
title: Stack-Based Buffer Overflow in Tenda AC1206 Web Interface
slug: 2026-08-tenda-ac1206-overflow
description: A stack-based buffer overflow in the Tenda AC1206 firmware version 15.03.06.23_multi_TD01 allows remote attackers to trigger memory corruption via the httpd web management interface.
date: "2026-08-14T06:06:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - network-security
  - buffer-overflow
vendors:
  - Tenda
products:
  - AC1206
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19788
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19788
  - https://github.com/lipenghai/iot_bug/blob/main/Tenda/AC12/1.md
rules:
  - title: Detects CVE-2026-19788 Exploitation - Overflow in SetOnlineDevName
    description: Detects attempts to exploit the stack-based buffer overflow in the Tenda AC1206 by identifying oversized input to the devName argument
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable remote management on Tenda AC1206 devices
      owner: IT Operations
      due: 24h
      evidence: High CVSS score and public availability of exploit
  hunt_leads:
    - lead: Search web logs for POST requests to /goform/SetOnlineDevName
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability exists in the SetOnlineDevName file
  mitigation_plan:
    - priority: immediate
      action: Restrict web management interface to local network
      owner: IT Operations
      addresses: CVE-2026-19788
      evidence: Remote exploitation vector confirmed
---

A vulnerability identified as CVE-2026-19788 affects the Tenda AC1206 router, specifically firmware version 15.03.06.23_multi_TD01. The issue resides within the httpd web management interface, where the function 'set_device_name' within the file '/goform/SetOnlineDevName' fails to properly validate the input provided to the 'devName' argument. This failure leads to a stack-based buffer overflow when a maliciously crafted input is processed. Because the interface is accessible remotely, an attacker can leverage this flaw to trigger an overflow, potentially leading to a denial of service or arbitrary code execution with the privileges of the web service. Proof-of-concept exploit code has been made public, increasing the risk of exploitation by unauthorized actors against internet-exposed devices.

## Attack Chain

1. Attacker performs reconnaissance to identify Tenda AC1206 devices exposed to the internet.
2. Attacker authenticates to the target device's web management interface (httpd).
3. Attacker identifies the '/goform/SetOnlineDevName' endpoint.
4. Attacker crafts an HTTP POST request containing an excessively long string in the 'devName' parameter.
5. The httpd service passes the 'devName' value to the vulnerable 'set_device_name' function.
6. The lack of bounds checking causes the supplied input to overwrite adjacent memory on the stack.
7. Attacker successfully redirects program execution flow to arbitrary code, resulting in system compromise.

## Impact

Successful exploitation of CVE-2026-19788 allows a remote attacker to gain control over the affected Tenda AC1206 router. Given the function's role in system administration, this vulnerability could be used to facilitate persistent access, exfiltration of configuration data, or the hijacking of network traffic traversing the device. The impact is significant for home and small business users relying on this hardware for network security.

## Recommendation

* Immediately restrict access to the httpd web management interface to trusted local network segments only.
* Disable remote management features on the Tenda AC1206 router until a patch is applied.
* Monitor network traffic for HTTP POST requests directed at '/goform/SetOnlineDevName' that contain unusually large or anomalous strings in the 'devName' parameter.
* Deploy the Sigma rule below to detect potential exploitation attempts.
