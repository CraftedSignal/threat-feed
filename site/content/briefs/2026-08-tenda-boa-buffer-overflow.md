---
title: Buffer Overflow Vulnerability in Tenda HG10 Boa Web Server
slug: 2026-08-tenda-boa-buffer-overflow
description: A critical buffer overflow vulnerability (CVE-2026-82542) in the Boa Web Server component of Tenda HG10 allows remote unauthenticated attackers to trigger a crash or achieve code execution via the formIPv6Routing function.
date: "2026-08-30T15:10:52Z"
lastmod: "2026-09-06T04:43:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:tenda:hg10:*:*:*:*:*:*:*:*
vendors:
  - Tenda
products:
  - HG10 (300001138)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
cves:
  - id: CVE-2026-82542
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82542
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86165
rules:
  - title: Detects CVE-2026-82542 Exploitation - Buffer Overflow Attempt in formIPv6Routing
    description: Detects HTTP requests containing suspiciously long 'destNet' parameters directed at the Boa Web Server admin endpoint, indicative of a buffer overflow attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-86165 Exploitation - Malicious POST to formURL
    description: Detects exploitation attempts against CVE-2026-86165 by monitoring POST requests to /boaform/admin/formURL containing potential buffer overflow payloads in the Keywd or urlFQDN parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block access to /boaform/admin/formIPv6Routing from untrusted networks
      owner: SOC
      due: 24h
      evidence: CVE-2026-82542 remote exploitability
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate Tenda HG10 devices
      owner: IT Operations
      addresses: CVE-2026-82542
      evidence: NVD vulnerability details
updates:
  - at: "2026-09-06T04:43:33Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-86165 Exploitation - Malicious POST to formURL'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-86165
---

CVE-2026-82542 describes a critical buffer overflow vulnerability found in the Tenda HG10 firmware version 300001138. The flaw resides in the 'formIPv6Routing' function within the '/boaform/admin/formIPv6Routing' URI, handled by the Boa Web Server component. An unauthenticated remote attacker can exploit this weakness by supplying a maliciously crafted 'destNet' argument in an HTTP request. Successful exploitation can lead to memory corruption, resulting in a denial-of-service condition or potentially remote code execution with the privileges of the web server. Given that public proof-of-concept exploit code is available, this vulnerability presents an immediate risk for network-connected devices.

## Impact

The vulnerability carries a CVSS v3.1 base score of 10.0, indicating the highest level of severity. If exploited, an attacker could remotely compromise the integrity and availability of Tenda HG10 devices. Widespread impact on home or small office networks is expected, as attackers may gain persistent access to the network or render the device unusable.

## Recommendation

1. Restrict management access to the Tenda HG10 web interface to trusted internal management subnets.
2. Monitor web server access logs for anomalous, high-length 'destNet' parameter values directed at the '/boaform/admin/formIPv6Routing' path.
3. Contact Tenda support for firmware patches addressing CVE-2026-82542; if no patch is available, disable remote management features.
