---
title: AWS-C-EventStream Out-of-Bounds Write Vulnerability (CVE-2026-5190)
slug: 2026-03-aws-c-event-stream-oob-write
description: CVE-2026-5190 is an out-of-bounds write vulnerability in the aws-c-event-stream library before version 0.6.0 that allows a malicious third-party server to cause memory corruption and potential arbitrary code execution on client applications.
date: "2026-03-31T18:16:59Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-5190
  - aws-c-event-stream
  - out-of-bounds write
  - code execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
cves:
  - id: CVE-2026-5190
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5190
  - https://aws.amazon.com/security/security-bulletins/2026-011-aws/
  - https://github.com/awslabs/aws-c-event-stream/releases/tag/v0.6.0
  - https://github.com/awslabs/aws-c-event-stream/security/advisories/GHSA-xvjw-fjq5-68hf
rules:
  - title: Potential Out-of-Bounds Write in aws-c-event-stream Client (Process)
    description: Detects anomalous process creation or memory access patterns that could be indicative of exploitation attempts related to CVE-2026-5190 when a client processes an event stream from a remote server.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Potential Out-of-Bounds Write in aws-c-event-stream Client (Network)
    description: Detects network connections to unusual ports or IP addresses by a client application after processing event streams, potentially indicative of a compromised client due to CVE-2026-5190.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-5190 is a critical security vulnerability affecting the aws-c-event-stream library, specifically versions prior to 0.6.0. The vulnerability is an out-of-bounds write issue in the streaming decoder component. This flaw enables a malicious third-party operating a server to send specially crafted event-stream messages to a client application using the vulnerable library. Successful exploitation could lead to memory corruption, ultimately allowing the attacker to achieve arbitrary code execution on the targeted client system. Organizations utilizing aws-c-event-stream in their client applications should prioritize upgrading to version 0.6.0 or later to mitigate this risk. The vulnerability was reported on March 31, 2026.

## Attack Chain

1.  Attacker sets up a malicious server designed to send crafted event-stream messages.
2.  A client application utilizing a vulnerable version (prior to 0.6.0) of the aws-c-event-stream library connects to the attacker's server.
3.  The attacker's server transmits a specially crafted event-stream message to the client.
4.  The vulnerable streaming decoder component within the aws-c-event-stream library processes the malicious message.
5.  Due to the out-of-bounds write vulnerability (CVE-2026-5190), the processing of the crafted message causes memory corruption on the client system.
6.  The memory corruption leads to a buffer overflow or similar memory safety issue.
7.  The attacker leverages the memory corruption to overwrite critical data or inject malicious code into memory.
8.  The injected code is executed, granting the attacker arbitrary code execution on the client system. The attacker can then perform actions such as data exfiltration, system compromise, or further lateral movement.

## Impact

Successful exploitation of CVE-2026-5190 allows a remote attacker to execute arbitrary code on a client system utilizing a vulnerable version of the aws-c-event-stream library. This could lead to complete system compromise, data theft, or the installation of malware. The potential impact is especially significant for applications that rely on event streams for critical functionality, such as real-time data processing or inter-process communication. While the number of affected applications is unknown, any application using a vulnerable version is at risk until patched.

## Recommendation

*   Upgrade all installations of the `aws-c-event-stream` library to version 0.6.0 or later to remediate CVE-2026-5190.
*   Implement network monitoring to detect potentially malicious event-stream messages being sent from third-party servers to client applications. Focus on anomalies in message size, structure, or content that could indicate exploitation attempts (requires custom network rules).
*   Enable verbose logging for applications utilizing `aws-c-event-stream` to capture detailed information about event-stream message processing and memory allocation patterns. This will aid in identifying potential exploitation attempts or debugging memory corruption issues.
