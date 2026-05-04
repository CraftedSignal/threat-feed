---
title: Potential Protocol Tunneling via Cloudflared
slug: 2026-05-cloudflared-tunnel
description: Adversaries may abuse Cloudflare Tunnel (cloudflared) on Windows systems to proxy command and control traffic or exfiltrate data through Cloudflare's edge, evading direct connection blocking.
date: "2026-05-05T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloudflare
  - tunneling
  - command and control
  - proxy
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
  - Cloudflare
products:
  - M365 Defender
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
references:
  - https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/tunnel-useful-commands/
  - https://attack.mitre.org/techniques/T1572/
iocs:
  - type: domain
    value: trycloudflare.com
ioc_counts:
  domain: 1
rules:
  - title: Cloudflared Tunnel Execution
    description: Detects the execution of Cloudflare Tunnel (cloudflared.exe) with the 'tunnel' argument, indicating potential protocol tunneling.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - process_creation
      - windows
  - title: Cloudflared Process Code Signature
    description: Detects cloudflared process with a Cloudflare, Inc. code signature.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Cloudflare Tunnel (cloudflared) is a legitimate tool for exposing local services through Cloudflare's edge. This tool can be abused by adversaries to create quick or named tunnels for command and control, data exfiltration, or ingress tool transfer while evading direct connection blocking. The adversary may utilize quick tunnels (e.g. `tunnel --url http://127.0.0.1:80`) or named tunnels to proxy command and control traffic. This activity began to be tracked around March 2026. Defenders should be aware of suspicious execution of cloudflared, especially from unusual locations, to detect potential misuse of this tool for malicious purposes.

## Attack Chain

1. An attacker gains initial access to a Windows system, potentially through phishing or exploiting a vulnerability.
2. The attacker downloads the `cloudflared.exe` executable to the compromised system, potentially staging it in a temporary directory.
3. The attacker executes `cloudflared.exe` with the `tunnel` command and arguments such as `--url http://127.0.0.1:80` to create a quick tunnel, forwarding local traffic through Cloudflare's infrastructure.
4. The attacker configures a local service, such as a reverse proxy or command and control server, to listen on the specified localhost port (e.g., 80).
5. The attacker uses the Cloudflare tunnel to establish an encrypted connection to the local service, masking the origin of the traffic.
6. The attacker proxies command and control traffic through the Cloudflare tunnel, communicating with the compromised system without directly exposing its IP address.
7. Alternatively, the attacker exfiltrates sensitive data through the Cloudflare tunnel, routing it through Cloudflare's edge network.
8. The attacker maintains persistence by establishing scheduled tasks or autorun registry keys to ensure the Cloudflare tunnel is re-established upon system reboot.

## Impact

Successful exploitation allows adversaries to proxy command and control traffic, exfiltrate data, or facilitate ingress tool transfer while evading direct connection blocking. This can lead to data breaches, system compromise, and prolonged unauthorized access. While the total number of victims is unknown, organizations using Windows systems are at risk.

## Recommendation

*   Monitor process creation events for execution of `cloudflared.exe` with the `tunnel` argument to identify potential misuse of Cloudflare Tunnel (see rule: "Potential Protocol Tunneling via Cloudflared").
*   Correlate network connection logs with process execution events to identify outbound connections to Cloudflare IPs or `trycloudflare.com`-style hostnames originating from `cloudflared.exe`.
*   Implement a process allowlist to restrict execution of `cloudflared.exe` to authorized locations (e.g., `C:\\Program Files\\Cloudflare\\`).
*   Monitor Windows Security Event Logs for suspicious logon or execution from the same context as `cloudflared.exe` processes.
*   Block the domain `trycloudflare.com` at the DNS resolver to prevent connections to attacker-controlled Cloudflare tunnels (see IOCs).
