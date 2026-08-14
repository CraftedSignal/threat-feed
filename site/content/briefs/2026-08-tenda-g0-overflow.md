---
title: Stack-Based Buffer Overflow in Tenda G0 Web Management Interface
slug: 2026-08-tenda-g0-overflow
description: Tenda G0 routers through version 20260625 contain a stack-based buffer overflow in the web management interface that allows remote attackers to trigger arbitrary code execution via crafted HTTP requests.
date: "2026-08-14T06:06:28Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Tenda
products:
  - G0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19790
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19790
  - https://github.com/lipenghai/iot_bug/blob/main/Tenda/G0/1.md
  - https://vuldb.com/vuln/389757
rules:
  - title: Detects CVE-2026-19790 Exploitation - Buffer Overflow via formSetPortMirror
    description: Detects potential exploitation attempts of the stack-based buffer overflow in the Tenda G0 'formSetPortMirror' function by monitoring for suspicious POST requests.
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
    - IT Operations
  immediate_actions:
    - action: Patch affected Tenda G0 devices to firmware version > 20260625
      owner: IT Operations
      due: 48h
      evidence: Source advisory for CVE-2026-19790
  mitigation_plan:
    - priority: immediate
      action: Restrict web management interface to internal/trusted IPs
      owner: IT Operations
      addresses: CVE-2026-19790
      evidence: Mitigation for remote exploitation risk
---

A stack-based buffer overflow vulnerability (CVE-2026-19790) has been identified in Tenda G0 routers running firmware versions up to 20260625. The flaw resides within the 'formSetPortMirror' function, which handles the 'portMirrorMirroredPorts' argument during requests to the '/goform/module' endpoint of the 'httpd' web management interface. By sending a specially crafted request with an overly long value for the 'portMirrorMirroredPorts' argument, a remote, authenticated attacker can overwrite stack memory. This vulnerability potentially allows for the execution of arbitrary code with the privileges of the web service. As proof-of-concept exploit code is publicly available, defenders should prioritize patching or restricting access to the administrative web interface.

## Attack Chain

1. The attacker identifies an internet-facing Tenda G0 device with the web management interface exposed.
2. The attacker performs authentication against the 'httpd' web service to obtain a valid session.
3. The attacker crafts an HTTP POST request targeting the '/goform/module' endpoint.
4. The request is populated with the 'portMirrorMirroredPorts' argument containing a malicious, oversized payload.
5. The 'formSetPortMirror' function processes the input without sufficient bounds checking.
6. The input triggers a stack-based buffer overflow, overwriting adjacent memory and the instruction pointer.
7. The attacker directs the flow of execution to a controlled payload, achieving arbitrary command execution.

## Impact

Successful exploitation allows for complete compromise of the affected Tenda G0 router, potentially leading to unauthorized data access, network interception, or the use of the device as an initial access point or proxy for further lateral movement within the local network. 

## Recommendation

- Immediately update the Tenda G0 firmware to the latest available version beyond 20260625 to mitigate CVE-2026-19790.
- Deploy the Sigma rule below to detect exploitation attempts against the '/goform/module' endpoint in web access logs.
- Restrict access to the router's web management interface to trusted internal IP addresses only.
- Monitor network traffic for unusual or highly repetitive POST requests to the '/goform/module' URI.
