---
title: Microsoft QUIC Remote Elevation of Privilege Vulnerability (CVE-2026-32179)
slug: 2024-01-03-msquic-privesc
description: CVE-2026-32179 is a critical remote elevation of privilege vulnerability in Microsoft QUIC caused by improper input validation during ACK frame decoding, potentially allowing an attacker to gain elevated privileges over the network.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - msquic
  - privilege-escalation
  - windows
vendors:
  - Microsoft
products:
  - Microsoft QUIC
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-gvvw-8j96-8g5r
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32179
rules:
  - title: Detect Suspicious Process Execution Post MsQuic Connection
    description: Detects suspicious process execution after a QUIC connection, potentially indicating post-exploitation activity related to CVE-2026-32179.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Microsoft.Native.Quic.MsQuic.dll Loaded by Unexpected Processes
    description: Detects Microsoft.Native.Quic.MsQuic.dll being loaded by processes that typically don't use it, which might suggest an attempt to exploit CVE-2026-32179.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - image_load
      - windows
rules_count: 2
---

Microsoft QUIC, a general-purpose transport protocol, is vulnerable to a critical elevation of privilege vulnerability identified as CVE-2026-32179. This vulnerability stems from improper input validation within the MsQuic component when decoding ACK frames, specifically an integer underflow. Exploitation of this vulnerability allows a remote attacker to gain elevated privileges on the target system. The affected packages include nuget/Microsoft.Native.Quic.MsQuic.OpenSSL and nuget/Microsoft.Native.Quic.MsQuic.Schannel, specifically versions before 2.4.18 and versions between 2.5.0-ci.532574 and 2.5.7. Defenders should prioritize patching vulnerable systems to mitigate the risk of exploitation.

## Attack Chain

1.  The attacker establishes a QUIC connection to a vulnerable server running a Microsoft QUIC implementation.
2.  The attacker crafts a malicious QUIC ACK frame with a specific sequence number designed to trigger an integer underflow during decoding.
3.  The vulnerable MsQuic library attempts to parse the crafted ACK frame, leading to an integer underflow during sequence number processing.
4.  The integer underflow corrupts internal data structures used for managing QUIC connections and stream state.
5.  The memory corruption allows the attacker to overwrite critical security-related data, such as access control lists (ACLs) or privilege levels.
6.  The attacker triggers the execution of a function or code path that relies on the corrupted security data.
7.  Due to the corrupted security data, the attacker gains elevated privileges within the context of the MsQuic process.
8.  The attacker leverages the elevated privileges to perform unauthorized actions, such as accessing sensitive data or executing arbitrary code on the system.

## Impact

Successful exploitation of CVE-2026-32179 allows an attacker to elevate their privileges on the target system. This can lead to complete system compromise, including unauthorized data access, modification, and deletion. The vulnerability affects systems running vulnerable versions of Microsoft QUIC, potentially impacting a wide range of services and applications that rely on the protocol. The observed damage would be unauthorized privilege escalation leading to a complete compromise of the target machine.

## Recommendation

*   Apply the Microsoft patch for CVE-2026-32179 to affected systems running Microsoft QUIC.
*   Monitor network traffic for malformed QUIC ACK frames indicative of exploitation attempts using a network intrusion detection system (NIDS).
*   Enable process creation logging and monitor for unexpected processes running with elevated privileges after a QUIC connection is established. This can aid in detecting post-exploitation activity.
