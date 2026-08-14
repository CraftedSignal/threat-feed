---
title: Remote Stack-Based Buffer Overflow in Tenda W20E
slug: 2026-08-tenda-buffer-overflow
description: A stack-based buffer overflow vulnerability in Tenda W20E firmware allows authenticated remote attackers to achieve potential code execution via the QoS Edit component.
date: "2026-08-14T14:11:56Z"
lastmod: "2026-08-14T14:13:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-19822
  - vulnerability
  - remote-code-execution
  - cve-2026-19823
  - buffer-overflow
  - rce
  - network-infrastructure
vendors:
  - Tenda
products:
  - W20E (15.11.0.6(1068_1546_841)_CN_TDC)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Successful exploitation may lead to remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Performing a manipulation of the argument qosIndex results in stack-based buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-19822
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19822
  - https://vuldb.com/vuln/389955
  - https://github.com/paueger/mycve/blob/main/Tenda_W20E/3.md
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19823
  - https://vuldb.com/cve/CVE-2026-19823
  - https://github.com/paueger/mycve/blob/main/Tenda_W20E/4.md
rules:
  - title: Detects CVE-2026-19822 Exploitation - Malicious qosListConnecttedNum POST Request
    description: Detects potential exploitation attempts of CVE-2026-19822 by monitoring POST requests to /goform/editQos containing unexpected input in the qosListConnecttedNum argument.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-19823 Exploitation - HTTP POST to /goform/delQos
    description: Detects exploitation attempts against CVE-2026-19823 where an attacker sends a POST request to /goform/delQos with suspicious qosIndex values.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1210
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Tenda W20E firmware
      owner: IT Operations
      due: 48h
      evidence: Source identifies specific affected firmware version
  mitigation_plan:
    - priority: immediate
      action: Restrict web management interface to trusted IPs
      owner: IT Operations
      addresses: CVE-2026-19822
      evidence: Exploit is remote
updates:
  - at: "2026-08-14T14:13:09Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-19823 Exploitation - HTTP POST to /goform/delQos'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19823
---

A stack-based buffer overflow vulnerability has been identified in Tenda W20E firmware version 15.11.0.6(1068_1546_841)_CN_TDC. The flaw resides within the QoS Edit component, specifically in the 'lstAdd' function called by the '/goform/editQos' endpoint. An attacker can trigger this condition by supplying a malicious payload to the 'qosListConnecttedNum' argument. The vulnerability, tracked as CVE-2026-19822, is exploitable remotely and proof-of-concept exploit code is publicly available. Given the potential for remote code execution, this represents a significant security risk for the impacted network gateway hardware.

## Attack Chain

1. Attacker performs network reconnaissance to identify Tenda W20E devices exposed to the internet.
2. Attacker establishes an authenticated session with the target device.
3. Attacker crafts an HTTP POST request targeting the /goform/editQos endpoint.
4. Attacker inserts a specially crafted, oversized value into the qosListConnecttedNum parameter.
5. The application passes the input to the vulnerable lstAdd function without proper bounds checking.
6. The excessive data overflows the allocated buffer on the stack.
7. The attacker overwrites return addresses or other critical stack data to hijack the control flow.
8. Execution of arbitrary code or denial of service is achieved on the affected device.

## Impact

Successful exploitation of this vulnerability allows for remote code execution on the Tenda W20E router. Given the position of these devices as network gateways, an attacker gaining code execution could facilitate lateral movement into the protected network, intercept traffic, or perform man-in-the-middle attacks. As of the time of reporting, the vulnerability is public and exploit material is accessible, increasing the likelihood of opportunistic exploitation against vulnerable firmware versions.

## Recommendation

Prioritized actions for security operations and IT teams:
- Check internal inventory for Tenda W20E devices running the affected firmware version 15.11.0.6(1068_1546_841)_CN_TDC.
- Apply the latest security patches provided by Tenda if available for this model.
- Restrict access to the device web administration interface (/goform/editQos) to trusted management subnets only.
- Deploy web application firewall (WAF) or intrusion detection system (IDS) rules to inspect and block HTTP requests containing abnormally long strings in the qosListConnecttedNum argument.
