---
title: strongSwan 5.9.13 libsimaka EAP-SIM/AKA Heap Buffer Overflow Vulnerability
slug: 2026-05-strongswan-heap-overflow
description: A remote exploit is available for strongSwan 5.9.13 exploiting a heap buffer overflow in the libsimaka EAP-SIM/AKA module (CVE-2026-35330), enabling pre-authentication exploitation via a malformed EAP-SIM/AKA payload.
date: "2026-05-29T06:21:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - strongSwan
  - heap-overflow
  - eap-sim
  - eap-aka
  - CVE-2026-35330
  - exploit
vendors:
  - strongSwan
products:
  - strongSwan <= 5.9.13
affected_os:
  - Debian 12
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.exploit-db.com/exploits/52587
  - https://github.com/strongswan/strongswan/commit/aa5aaebc33
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35330
  - https://github.com/JohannesLks/CVE-2026-35330
rules:
  - title: Detect strongSwan libsimaka Heap Overflow Attempt
    description: Detects CVE-2026-35330 exploitation — monitors for EAP-SIM/AKA messages with a zero-length AT_RAND attribute, indicating a heap overflow attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect strongSwan libsimaka Crash - ASan Heap Overflow Write
    description: Detects CVE-2026-35330 exploitation — monitors process creation output for AddressSanitizer heap-buffer-overflow WRITE when processing EAP-SIM/AKA payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A public remote exploit has been released targeting strongSwan version 5.9.13, specifically exploiting a heap buffer overflow vulnerability (CVE-2026-35330) within the libsimaka EAP-SIM/AKA module. The vulnerability resides in the `parse_attributes()` function in `simaka_message.c`. This function calculates the attribute data length without validating against `hdr->length == 0`, leading to an integer underflow when `hdr->length` is 0. This results in a small memory allocation followed by an oversized `memcpy`, triggering a heap buffer overflow. The exploit, identified as EDB-52587, highlights the pre-authentication nature of the vulnerability, as the malicious payload is processed during IKE_AUTH before peer authentication is completed. This vulnerability poses a critical risk to systems running vulnerable strongSwan versions with the EAP-SIM or EAP-AKA plugin enabled.

## Attack Chain

1. An attacker sends a malicious IKE_AUTH request to a vulnerable strongSwan server.
2. The request contains an EAP-SIM/AKA payload crafted to trigger the vulnerability.
3. The `simaka_message_create_from_payload()` function processes the received data.
4. Inside `parse_attributes()` in `simaka_message.c`, the code calculates the attribute data length using `hdr->length * 4 - 4`.
5. If `hdr->length` is 0, the calculation results in an integer underflow, leading to a large value being used for the size of the data to be copied.
6. The code allocates a small chunk of memory using `malloc(sizeof(attr_t) + data.len)`.
7. An oversized `memcpy` operation is performed, copying data beyond the allocated buffer, leading to a heap buffer overflow.
8. This overflow can lead to arbitrary code execution, potentially granting the attacker complete control of the system.

## Impact

Successful exploitation of this vulnerability (CVE-2026-35330) allows a remote, unauthenticated attacker to achieve arbitrary code execution on a vulnerable strongSwan server. Given that strongSwan is frequently used to establish VPN connections, successful exploitation could grant an attacker unauthorized access to internal networks and sensitive data. The Exploit-DB entry confirms the exploit's feasibility.

## Recommendation

*   Upgrade strongSwan to a version patched against CVE-2026-35330. The fix is available in master >= aa5aaebc33 as referenced in the Exploit-DB entry.
*   Deploy the Sigma rule "Detect strongSwan libsimaka Heap Overflow Attempt" to identify potential exploitation attempts by monitoring for EAP-SIM/AKA messages with a zero-length attribute, as described in the vulnerability details.
*   Apply input validation on EAP-SIM/AKA attribute lengths to prevent the integer underflow, addressing the root cause described in the exploit details.
