---
title: Remote Buffer Overflow Vulnerability in PCMan FTP Server
slug: 2026-08-pcman-buffer-overflow
description: PCMan FTP Server 2.0.7 is vulnerable to a remote buffer overflow via the REST command (CVE-2025-4871), allowing for unauthenticated remote code execution.
date: "2026-08-18T14:29:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pcman:ftp_server:2.0.7:*:*:*:*:*:*:*
vendors:
  - PCMan
products:
  - PCMan FTP Server (2.0.7)
affected_os:
  - Windows XP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The vulnerability can be triggered by sending a specially crafted 'REST' command to the server, which leads to memory corruption and potential remote code execution.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Exploit targets Windows XP systems to gain a shell reverse TCP connection.
    confidence_band: high
cves:
  - id: CVE-2025-4871
    cvss: 7.3
    epss: 0.00649
references:
  - https://www.exploit-db.com/exploits/52657
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all servers running legacy FTP services and restrict network access to port 21.
      owner: IT Operations
      due: 24h
      evidence: Public exploit available for CVE-2025-4871.
  mitigation_plan:
    - priority: immediate
      action: Replace PCMan FTP Server with a modern, maintained SFTP/FTPS solution.
      owner: IT Operations
      addresses: CVE-2025-4871
      evidence: Legacy software unpatched against critical RCE.
---

A remote buffer overflow vulnerability has been identified in PCMan FTP Server version 2.0.7 (CVE-2025-4871). The vulnerability allows an unauthenticated attacker to trigger memory corruption by sending a specially crafted 'REST' command to the vulnerable FTP service. Successful exploitation enables the execution of arbitrary code under the context of the FTP server process. A functional proof-of-concept exploit script is publicly available, which uses a JMP ESP instruction to redirect execution flow to attacker-supplied shellcode. This vulnerability poses a significant risk to any systems still running this legacy FTP server, particularly in environments where it may be exposed to the network.

## Attack Chain

1. The attacker establishes a TCP connection to the target server on port 21.
2. The attacker authenticates or uses 'anonymous' login if permitted by the server configuration.
3. The attacker crafts a malicious payload containing 2006 bytes of junk data (offset).
4. The payload appends a JMP ESP memory address to overwrite the return address on the stack.
5. The payload includes a NOP sled to facilitate reliable shellcode execution.
6. The attacker sends the malicious payload encapsulated within a 'REST' command via the established FTP socket.
7. The application fails to validate the input length of the REST command, resulting in a buffer overflow.
8. The execution flow is redirected to the attacker-supplied shellcode (e.g., a reverse TCP shell), granting the attacker remote control.

## Impact

Successful exploitation results in full remote code execution under the privileges of the service account running the PCMan FTP Server. Given the nature of this software, it is often run with elevated or system-level privileges on legacy Windows systems, providing an attacker with persistent access, the ability to exfiltrate sensitive files, or use the compromised host as a pivot point in the network.

## Recommendation

Prioritize the decommissioning of legacy FTP servers like PCMan 2.0.7, as they lack modern security mitigations. If replacement is not immediately possible, implement the following:
- Block access to port 21 from untrusted network segments.
- Deploy network-based intrusion detection to inspect FTP traffic for anomalous, overly long strings within the 'REST' command.
- Implement EDR process-creation logging to detect suspicious child processes spawned by the FTP service.
