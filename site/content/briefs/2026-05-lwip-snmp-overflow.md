---
title: lwIP SNMPv3 USM Handler Stack-Based Buffer Overflow (CVE-2026-8836)
slug: 2026-05-lwip-snmp-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-8836) exists in lwIP up to version 2.2.1 within the snmpv3 USM Handler, allowing remote attackers to execute arbitrary code by manipulating the `msgAuthenticationParameters` argument in the `snmp_parse_inbound_frame` function.
date: "2026-05-18T19:17:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - snmp
  - buffer_overflow
  - rce
  - CVE-2026-8836
products:
  - lwIP (<= 2.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-8836
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8836
  - https://cgit.git.savannah.gnu.org/cgit/lwip.git/commit/?id=0c957ec03054eb6c8205e9c9d1d05d90ada3898c
  - https://github.com/lwip-tcpip/lwip/commit/0c957ec03054eb6c8205e9c9d1d05d90ada3898c
  - https://savannah.nongnu.org/bugs/?68194
  - https://vuldb.com/submit/829798
  - https://vuldb.com/vuln/364474
  - https://vuldb.com/vuln/364474/cti
rules:
  - title: Detect CVE-2026-8836 Exploitation Attempt via Malformed SNMP Packet
    description: Detects CVE-2026-8836 exploitation attempt via oversized msgAuthenticationParameters in SNMPv3 packets
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
  - title: Detect Excessive SNMPv3 Authentication Failures
    description: Detects a high number of SNMPv3 authentication failures from a single source, potentially indicating brute-forcing of authentication parameters leading to a buffer overflow.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1110.003
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

A stack-based buffer overflow vulnerability, identified as CVE-2026-8836, has been discovered in lwIP versions up to 2.2.1. The vulnerability resides within the `snmpv3 USM Handler` component, specifically in the `snmp_parse_inbound_frame` function of the `src/apps/snmp/snmp_msg.c` file. By manipulating the `msgAuthenticationParameters` argument, a remote attacker can trigger a buffer overflow, potentially leading to arbitrary code execution. The patch addressing this vulnerability is identified by the commit hash `0c957ec03054eb6c8205e9c9d1d05d90ada3898c`. This vulnerability poses a significant risk as it can be exploited remotely without authentication.

## Attack Chain

1. The attacker identifies a vulnerable lwIP instance with SNMPv3 USM enabled.
2. The attacker crafts a malicious SNMPv3 packet targeting the `snmp_parse_inbound_frame` function.
3. The crafted packet includes a `msgAuthenticationParameters` argument designed to exceed the buffer's capacity.
4. The `snmp_parse_inbound_frame` function processes the malformed SNMPv3 packet without proper bounds checking.
5. The oversized `msgAuthenticationParameters` argument overwrites adjacent memory on the stack, including return addresses.
6. Upon function return, the overwritten return address is used, redirecting execution flow to attacker-controlled code.
7. The attacker gains arbitrary code execution within the context of the lwIP process.
8. The attacker can then use this code execution to further compromise the system, potentially leading to data exfiltration or denial of service.

## Impact

Successful exploitation of CVE-2026-8836 allows a remote attacker to execute arbitrary code on the vulnerable system. Given the widespread use of lwIP in embedded devices and network appliances, a large number of devices are potentially affected. A successful attack could lead to complete system compromise, allowing the attacker to steal sensitive data, disrupt network services, or use the compromised device as a bot in a larger botnet. The CVSS v3.1 score of 9.8 highlights the critical severity of this vulnerability.

## Recommendation

*   Apply the patch identified by commit hash `0c957ec03054eb6c8205e9c9d1d05d90ada3898c` to address the buffer overflow.
*   Monitor network traffic for malformed SNMPv3 packets, especially those with unusually large `msgAuthenticationParameters` using the provided Sigma rules.
*   Consider disabling SNMPv3 USM if it is not required to reduce attack surface.
*   Deploy the Sigma rule "Detect CVE-2026-8836 Exploitation Attempt via Malformed SNMP Packet" to detect potential exploitation attempts.
