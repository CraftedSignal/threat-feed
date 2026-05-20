---
title: Rsync Integer Overflow Vulnerability Leading to Information Disclosure (CVE-2026-43618)
slug: 2026-05-rsync-integer-overflow
description: Rsync versions 3.4.2 and prior contain an integer overflow vulnerability (CVE-2026-43618) in the compressed-token decoder, allowing a malicious sender to trigger out-of-bounds memory access on the receiver and disclose sensitive process memory.
date: "2026-05-20T02:18:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - integer overflow
  - information disclosure
  - rsync
vendors:
  - rsync
products:
  - rsync <= 3.4.2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1068
    technique_name: Exploitation for Credential Access
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Credential Access
cves:
  - id: CVE-2026-43618
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43618
  - CVE-2026-43618
rules:
  - title: Detect Rsync CVE-2026-43618 Integer Overflow Attempt
    description: Detects CVE-2026-43618 exploitation attempt via monitoring rsync process execution. This rule is based on network traffic characteristics as a definitive indicator is difficult to implement.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Rsync, a widely used utility for synchronizing files between computer systems, is susceptible to an integer overflow vulnerability (CVE-2026-43618) within its compressed-token decoder. Specifically, versions 3.4.2 and earlier fail to adequately validate a 32-bit signed counter, leading to an overflow condition. A malicious rsync sender can exploit this flaw by crafting a specially designed data stream that triggers the overflow during decompression on the receiving end. This overflow can cause the receiver process to read data outside of the intended buffer boundaries. Successful exploitation results in the disclosure of sensitive process memory contents.

## Attack Chain

1.  Attacker crafts a malicious data stream designed to exploit the integer overflow in the rsync compressed-token decoder.
2.  The attacker initiates an rsync session with a vulnerable rsync server (version 3.4.2 or prior).
3.  During data transfer, the malicious data stream is sent to the rsync server.
4.  The rsync server attempts to decompress the data stream using the vulnerable compressed-token decoder.
5.  The 32-bit signed counter overflows due to the crafted data stream.
6.  The overflow causes the rsync server process to read data from memory locations outside the intended buffer.
7.  Sensitive information, such as environment variables, passwords, heap data, stack data, and library memory pointers, are exposed.
8.  The attacker gains access to the disclosed memory contents, potentially facilitating further exploitation and bypassing ASLR.

## Impact

Successful exploitation of CVE-2026-43618 leads to information disclosure on the affected system. An attacker can potentially access sensitive data residing in the rsync process memory, including environment variables, passwords, and memory addresses. This leaked information can be leveraged to bypass ASLR, escalate privileges, and perform lateral movement within the network. The vulnerability poses a significant risk to the confidentiality and integrity of the affected systems.

## Recommendation

*   Upgrade rsync to a version higher than 3.4.2 to patch CVE-2026-43618.
*   Deploy the Sigma rule `Detect Rsync CVE-2026-43618 Integer Overflow Attempt` to detect potential exploitation attempts by monitoring process command-line arguments.
*   Review systems running vulnerable rsync versions for suspicious network connections and memory access patterns.
