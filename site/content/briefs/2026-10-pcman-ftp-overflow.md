---
title: Remote Code Execution in PCMan FTP Server
slug: 2026-10-pcman-ftp-overflow
description: PCMan FTP Server 2.0 is vulnerable to a stack-based buffer overflow via the pwd command, allowing unauthenticated remote code execution.
date: "2026-10-19T18:22:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pcman:ftp_server:2.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - legacy-software
products:
  - PCMan FTP Server (2.0)
affected_os:
  - Windows XP
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A stack overflow occurs when the server accepts the incoming request, allowing the attacker to gain unauthorized access to the system.
    confidence_band: high
cves:
  - id: CVE-2024-58299
    cvss: 9.8
    epss: 0.00828
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58299
  - https://www.exploit-db.com/exploits/51767
  - https://www.vulncheck.com/advisories/pcman-ftp-server-remote-buffer-overflow-via-pwd-command
rules:
  - title: Detect Potential CVE-2024-58299 Exploitation
    description: Detects anomalous FTP pwd command lengths that could indicate a buffer overflow attempt against PCMan FTP Server
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - network_connection
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and decommission instances of PCMan FTP Server 2.0.
      owner: IT Operations
      due: 24h
      evidence: CVE-2024-58299 critical severity and active PoC availability.
  hunt_leads:
    - lead: Inspect historical FTP logs for long PWD commands.
      technique_id: T1203
      data_needed:
        - Network logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Public exploit scripts send a 2007-byte padding sequence.
  mitigation_plan:
    - priority: immediate
      action: Replace PCMan FTP Server with a modern, maintained alternative.
      owner: IT Operations
      addresses: CVE-2024-58299
      evidence: Vulnerability is inherent to the legacy software architecture.
  gaps:
    - Lack of enterprise-wide asset visibility for legacy FTP services.
---

PCMan FTP Server version 2.0 contains a critical buffer overflow vulnerability identified as CVE-2024-58299. The vulnerability is triggered when the server processes a crafted 'pwd' command containing an excessively long string. This buffer overflow permits an unauthenticated remote attacker to overwrite the stack, leading to arbitrary code execution on the target system. Proof-of-concept exploits for this vulnerability have been publicly released, including implementations in Python and Ruby, as well as an established Metasploit module. This flaw poses a significant risk to any environment still utilizing the legacy PCMan FTP Server 2.0 software, as exploitation does not require prior authentication or user interaction.

## Attack Chain

1. The attacker performs network reconnaissance to identify targets running PCMan FTP Server 2.0 on port 21.
2. The attacker establishes a TCP connection to the target's FTP service.
3. The attacker performs initial authentication or leverages anonymous access, which is often enabled by default in this server version.
4. The attacker sends a crafted 'pwd' command containing a 2007-byte padding sequence followed by a custom return address (e.g., JMP ESP).
5. The server process crashes or redirects execution flow as it attempts to process the oversized 'pwd' argument, triggering the stack overflow.
6. The injected shellcode, appended to the request, is executed with the privileges of the FTP service process.
7. The attacker establishes a reverse TCP meterpreter session or similar payload to achieve remote command-and-control access.
8. The attacker gains unauthorized control over the host system, typically with administrative or system privileges depending on the service execution context.

## Impact

Successful exploitation results in full system compromise. As the FTP service often runs with high privileges, attackers can gain administrative access, exfiltrate sensitive files, or deploy additional malware. Given the publicly available PoC scripts and Metasploit modules, the barrier to entry for this exploit is low for actors targeting legacy infrastructure.

## Recommendation

Prioritize the decommissioning of PCMan FTP Server 2.0. As this is legacy software, immediate migration to a modern, supported FTP or SFTP solution is the primary mitigation. Ensure network perimeter security blocks unauthorized access to port 21.
