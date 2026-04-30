---
title: Yokogawa CENTUM VP R6 and R7 Vulnerabilities Lead to Potential Denial of Service and Arbitrary Code Execution
slug: 2026-02-yokogawa-centum-vp-r6-r7
description: Multiple vulnerabilities in Yokogawa CENTUM VP R6 and R7 Vnet/IP Interface Package can be exploited by sending maliciously crafted packets, leading to denial-of-service or arbitrary code execution.
date: "2026-02-27T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - denial-of-service
  - out-of-bounds write
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1040
    technique_name: Network Sniffing
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-09
  - https://nvd.nist.gov/vuln/detail/CVE-2025-1924
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48019
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48020
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48021
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48022
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48023
  - https://web-material3.yokogawa.com/1/39281/files/YSAR-26-0002-E.pdf
rules:
  - title: Detect Possible Yokogawa CENTUM VP DoS Attempt via Malformed Packets
    description: Detects network connections with unusual characteristics that may indicate an attempt to exploit vulnerabilities in Yokogawa CENTUM VP systems, leading to a denial-of-service.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Vnet/IP Process Termination (Simulated)
    description: This rule simulates detection of a process termination, which is the result of some of the vulnerabilities. Adjust the Image to the actual Vnet/IP process name if known.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Yokogawa CENTUM VP is a distributed control system (DCS) used in critical infrastructure sectors such as critical manufacturing, energy, and food and agriculture worldwide. CISA has released an advisory detailing multiple vulnerabilities (CVE-2025-1924, CVE-2025-48019, CVE-2025-48020, CVE-2025-48021, CVE-2025-48022, CVE-2025-48023) affecting the Vnet/IP Interface Package for CENTUM VP R6 (VP6C3300) and R7 (VP7C3300) versions <= R1.07.00. Successful exploitation of these vulnerabilities could allow an attacker to terminate the software stack process, cause a denial-of-service condition, or execute arbitrary code. The vulnerabilities are triggered by receiving maliciously crafted network packets, posing a significant risk to industrial control systems relying on affected versions of Yokogawa CENTUM VP.

## Attack Chain

1.  Attacker identifies a vulnerable Yokogawa CENTUM VP system running Vnet/IP Interface Package for CENTUM VP R6 or R7 (<=R1.07.00) on the network.
2.  Attacker crafts a malicious network packet specifically designed to exploit one of the identified vulnerabilities (CVE-2025-1924, CVE-2025-48019, CVE-2025-48020, CVE-2025-48021, CVE-2025-48022, CVE-2025-48023).
3.  Attacker sends the malicious packet to the vulnerable system.
4.  If exploiting CVE-2025-1924 (Out-of-bounds Write), the crafted packet triggers an out-of-bounds write, potentially overwriting critical memory regions.
5.  If exploiting CVE-2025-48019, CVE-2025-48020, CVE-2025-48021, or CVE-2025-48022 (Reachable Assertion, Integer Underflow), the crafted packet causes the Vnet/IP software stack process to terminate due to an assertion failure or integer underflow.
6.  If successful, the Vnet/IP communication functions stop, resulting in a denial-of-service condition, impacting the control and monitoring capabilities of the CENTUM VP system.
7.  (Potentially, for CVE-2025-1924) By carefully crafting the malicious packet and exploiting the out-of-bounds write, the attacker may achieve arbitrary code execution on the targeted system.
8.  Attacker could then leverage the code execution to gain further control of the system, potentially disrupting industrial processes or exfiltrating sensitive data.

## Impact

Successful exploitation of these vulnerabilities in Yokogawa CENTUM VP R6 and R7 could have significant consequences for organizations in critical infrastructure sectors. A denial-of-service condition can disrupt industrial processes, leading to production losses and potential safety hazards. Arbitrary code execution could allow attackers to gain complete control of the system, potentially leading to sabotage, data theft, or further attacks on the network. Given the widespread deployment of Yokogawa CENTUM VP systems globally, the impact could be significant across various industries.

## Recommendation

*   Apply the patch software R1.08.00 provided by Yokogawa to address the vulnerabilities (CVE-2025-1924, CVE-2025-48019, CVE-2025-48020, CVE-2025-48021, CVE-2025-48022, CVE-2025-48023).
*   Monitor network traffic for unexpected patterns or malformed packets targeting Yokogawa CENTUM VP systems using network intrusion detection systems (NIDS).
*   Consult Yokogawa advisory YSAR-26-0002 for detailed mitigation steps and implementation guidance: https://web-material3.yokogawa.com/1/39281/files/YSAR-26-0002-E.pdf
*   Implement network segmentation to isolate critical control systems from the broader network to limit the potential impact of a successful attack.
