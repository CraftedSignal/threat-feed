---
title: Cloudflare Tunnel (cloudflared) Abuse for Protocol Tunneling
slug: 2024-01-cloudflared-tunneling
description: Adversaries are abusing Cloudflare Tunnel (cloudflared) to create outbound tunnels and proxy command and control traffic, or exfiltrate data, evading direct connection blocking by routing traffic through Cloudflare's edge.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - protocol-tunneling
  - windows
vendors:
  - Cloudflare
products:
  - Cloudflare Tunnel
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
  - title: Detect Cloudflared Execution from Suspicious Location
    description: Detects cloudflared.exe execution from suspicious locations like the user's temp directory.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - process_creation
      - windows
  - title: Detect Cloudflared Process Name and Arguments
    description: Detects cloudflared.exe execution with tunnel arguments
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - process_creation
      - windows
  - title: Detect Cloudflared Code Signature
    description: Detects cloudflared.exe execution based on code signature of Cloudflare, Inc.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Cloudflare Tunnel (cloudflared) is a legitimate tool designed to expose local services securely through Cloudflare's network. Threat actors are abusing this tool to establish covert communication channels, proxy command and control (C2) traffic, and exfiltrate sensitive data. By leveraging Cloudflare's infrastructure, attackers can effectively bypass traditional network security measures and evade detection based on direct connection blocking. This technique allows for the creation of quick tunnels (e.g., using the `--url` parameter) or named tunnels, offering flexibility in establishing and maintaining a persistent presence within compromised environments. Defenders should be aware of unusual cloudflared process executions, especially when originating from non-standard locations or user profiles.

## Attack Chain

1.  The attacker gains initial access to a target Windows system, potentially through exploitation of a vulnerability or credential compromise.
2.  The attacker downloads the `cloudflared.exe` binary to the compromised host, often placing it in a non-standard directory such as `C:\Users\<username>\AppData\Local\Temp`.
3.  The attacker executes `cloudflared.exe` with the `tunnel` command and arguments to create a quick tunnel, mapping a local port (e.g., 127.0.0.1:8080) to a Cloudflare-provided endpoint.
4.  The attacker configures their C2 server or data exfiltration tool to communicate with the local port being tunneled by `cloudflared.exe`.
5.  All traffic between the compromised host and the C2 server or exfiltration point is now routed through the Cloudflare tunnel, masking the destination IP address and port.
6.  The attacker maintains persistence by scheduling a task or modifying a registry key to automatically restart the `cloudflared.exe` process after system reboots.
7.  The attacker uses the established tunnel to execute commands on the compromised host or to exfiltrate sensitive data to an external location.
8.  The attacker removes traces of the cloudflared installation and execution from the system logs to prevent detection, as much as possible.

## Impact

Successful exploitation of Cloudflare Tunnel can lead to significant compromise, including data exfiltration, command and control of infected systems, and the establishment of persistent backdoors. Due to the nature of tunneling through a legitimate service like Cloudflare, detection can be challenging. If successful, this could impact any organization utilizing Windows systems and can lead to financial loss and reputational damage. The number of victims and sectors targeted remain unknown, but this technique is a common method used to bypass network security.

## Recommendation

*   Monitor process creation events for `cloudflared.exe` executions, especially those originating from unusual locations like temporary directories (`C:\Users\<username>\AppData\Local\Temp`) using the Sigma rule `Detect Cloudflared Execution from Suspicious Location`.
*   Inspect command-line arguments of `cloudflared.exe` processes for the presence of `tunnel`, `--url`, or `tunnel run` to identify potential tunnel creation attempts as seen in the primary rule.
*   Monitor network connections for outbound traffic to Cloudflare IPs or domains like `trycloudflare.com` initiated by uncommon processes to identify potential tunneling activity, as described in the overview section.
*   Block the domain `trycloudflare.com` at the DNS resolver to prevent connections to potentially malicious Cloudflare tunnels, based on the IOC identified.
