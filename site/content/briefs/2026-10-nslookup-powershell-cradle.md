---
title: Suspicious PowerShell DNS Payload Extraction via Nslookup
slug: 2026-10-nslookup-powershell-cradle
description: Adversaries leverage nslookup within PowerShell execution flows to retrieve malicious payloads encoded in DNS TXT records, bypassing traditional network egress filtering.
date: "2026-10-14T08:16:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - powershell
  - dns-tunneling
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This cradle uses nslookup to extract payloads from DNS records.
    confidence_band: high
rules:
  - title: Detect Nslookup PowerShell Download Cradle
    description: Detects suspicious PowerShell download cradle using nslookup to extract payloads from DNS TXT records.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for suspicious nslookup activity
      owner: Detection Engineering
      due: 48h
      evidence: Source provides actionable rule for detection
---

This technique involves the use of the Windows 'nslookup' utility to facilitate data exfiltration or payload retrieval from remote DNS servers. By invoking 'nslookup' with specific query types, particularly TXT records, attackers can retrieve command-and-control instructions or small file fragments encoded directly within the DNS response. This method is frequently observed as part of a multi-stage PowerShell-based download cradle, where the attacker uses PowerShell to programmatically query DNS records for staging purposes. This technique is notable because it relies on the standard DNS protocol (port 53/UDP), which is often permitted through firewalls, allowing adversaries to bypass proxy or URL-filtering restrictions used to monitor HTTP/HTTPS traffic.

## Attack Chain

1. An attacker establishes initial access through a separate vector, such as a malicious script execution.
2. The attacker launches an instance of 'powershell.exe' or 'pwsh.exe' to execute a malicious payload.
3. The PowerShell script identifies an attacker-controlled authoritative DNS server.
4. The script spawns 'nslookup.exe' as a child process to perform a DNS query.
5. The query specifies the '-type=txt' or '-q=txt' flag to request encoded data from the DNS server.
6. The DNS server returns a TXT record containing the malicious payload or encoded commands.
7. The PowerShell process captures the output of the 'nslookup' command and reconstructs the payload in memory.
8. The final payload is executed or used to stage subsequent stages of the attack, such as shellcode injection or secondary malware retrieval.

## Impact

Successful execution of this technique enables adversaries to maintain communication with C2 infrastructure and retrieve payloads in environments where web-based outbound connections are heavily restricted. This allows for persistent command execution and data movement that remains invisible to standard web proxy or HTTPS inspection appliances, effectively extending the attacker's dwell time and operational capability.

## Recommendation

* Deploy the provided Sigma rule to detect the specific parent-child process relationship and command-line arguments associated with this technique.
* Monitor process execution logs for 'nslookup.exe' spawned by PowerShell or non-standard administrative processes.
* Analyze DNS query logs for anomalous spikes in TXT record requests, especially those targeting specific or suspicious domains.
* Restrict the ability for non-administrative users to execute command-line network utilities where possible.
