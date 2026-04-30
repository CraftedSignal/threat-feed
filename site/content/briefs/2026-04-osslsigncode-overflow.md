---
title: osslsigncode Stack Buffer Overflow Vulnerability (CVE-2026-39853)
slug: 2026-04-osslsigncode-overflow
description: A stack buffer overflow vulnerability (CVE-2026-39853) exists in osslsigncode versions prior to 2.12 due to insufficient validation of digest length during PKCS#7 signature verification, potentially leading to arbitrary code execution.
date: "2026-04-09T16:16:31Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - osslsigncode
  - buffer-overflow
  - authenticode
  - code-signing
  - CVE-2026-39853
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-39853
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39853
rules:
  - title: Detect osslsigncode Verify Command Execution
    description: Detects execution of the osslsigncode verify command, which is a prerequisite for exploiting CVE-2026-39853.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - linux
  - title: Detect Crash Related to osslsigncode
    description: Detects a crash or fault event where osslsigncode is the primary process.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A stack buffer overflow vulnerability has been identified in osslsigncode, a tool used for Authenticode signing and timestamping. Specifically, versions prior to 2.12 are susceptible to CVE-2026-39853. The vulnerability occurs during the verification of PKCS#7 signatures in PE, MSI, CAB, and script files. The code copies the digest value from a parsed SpcIndirectDataContent structure into a fixed-size stack buffer (64 bytes) without proper length validation. This allows an attacker to craft a malicious signed file containing an oversized digest field within the SpcIndirectDataContent structure. When a user attempts to verify this malicious file using a vulnerable version of osslsigncode, the resulting unbounded memcpy operation overflows the stack buffer, potentially corrupting adjacent stack state and leading to arbitrary code execution. This vulnerability has been addressed in osslsigncode version 2.12.

## Attack Chain

1.  Attacker crafts a malicious signed file (PE, MSI, CAB, or script) with an oversized digest field within the SpcIndirectDataContent structure of the PKCS#7 signature.
2.  The malicious file is distributed to a target user or system.
3.  The target system uses a vulnerable version of osslsigncode (prior to 2.12) to verify the signature of the malicious file using the command `osslsigncode verify`.
4.  During the signature verification process, osslsigncode parses the SpcIndirectDataContent structure.
5.  The vulnerable code attempts to copy the digest value from the parsed SpcIndirectDataContent into a fixed-size stack buffer (64 bytes) without proper length validation.
6.  Due to the oversized digest field, the `memcpy` operation overflows the stack buffer.
7.  The stack buffer overflow corrupts adjacent stack state, potentially overwriting return addresses or other critical data.
8.  The corrupted stack state leads to arbitrary code execution under the context of the osslsigncode process, granting the attacker control of the system.

## Impact

Successful exploitation of CVE-2026-39853 allows an attacker to execute arbitrary code on a system running a vulnerable version of osslsigncode. This can lead to complete system compromise, data exfiltration, or further malicious activities. While the specific number of affected systems is unknown, any system using osslsigncode for signature verification prior to version 2.12 is potentially vulnerable. The impact is significant, as it can undermine the trust placed in Authenticode signatures.

## Recommendation

*   Upgrade osslsigncode to version 2.12 or later to patch CVE-2026-39853 and prevent stack buffer overflows.
*   Monitor systems for unexpected crashes or unusual behavior associated with osslsigncode, which could indicate exploitation attempts.
*   Implement input validation and sanitization on digest lengths during signature verification to prevent similar vulnerabilities in other applications.
