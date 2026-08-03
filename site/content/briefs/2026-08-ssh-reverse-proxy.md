---
title: Detection of SSH Reverse Port Forwarding on Windows
slug: 2026-08-ssh-reverse-proxy
description: Adversaries are abusing native Windows OpenSSH and Plink binaries to establish unauthorized reverse SSH tunnels, bypassing inbound connectivity controls for C2 and lateral movement.
date: "2026-08-03T17:53:42Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - command-and-control
  - lateral-movement
  - proxy
  - tunneling
  - windows
vendors:
  - OpenSSH
  - PuTTY
products:
  - OpenSSH
  - Plink
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: Adversaries may abuse reverse forwarding to expose an internal service or proxy listener through an external SSH server, establishing an outbound tunnel that bypasses direct inbound connectivity controls.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: Identifies the use of Windows OpenSSH or Plink to create a reverse SSH port forward or reverse dynamic SOCKS proxy.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Adversaries may abuse reverse forwarding to expose an internal service or proxy listener through an external SSH server, establishing an outbound tunnel that bypasses direct inbound connectivity controls.
    confidence_band: high
references:
  - https://thedfirreport.com/2025/11/04/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
  - https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
rules:
  - title: Detect Potential SSH Reverse Port Forwarding
    description: Detects the use of Windows OpenSSH or Plink to create a reverse SSH port forward or reverse dynamic SOCKS proxy, which may indicate C2 or lateral movement.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1021.004
      - T1090.002
      - T1572
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line arguments to detect.
  hunt_leads:
    - lead: Search for historical process creation events for plink.exe or ssh.exe with -R arguments.
      technique_id: T1090.002
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Adversaries utilize these tools for persistence and C2.
---

Adversaries frequently abuse native and dual-use tools like Windows OpenSSH (ssh.exe) and PuTTY’s Plink (plink.exe) to establish unauthorized network tunnels. By utilizing the reverse port forwarding capabilities inherent in the SSH protocol, attackers can expose internal services or establish dynamic SOCKS proxies that route traffic outbound to an attacker-controlled listener. This technique effectively bypasses restrictive inbound firewall rules and network access control lists (ACLs) by initiating the connection from within the compromised environment. 

Defenders should monitor process creation events for these specific binaries when executed with arguments indicative of reverse forwarding, such as "-R" or "-oRemoteForward". This activity is commonly observed during the lateral movement and command-and-control phases of post-exploitation, as documented in reports detailing ransomware campaigns and domain compromise scenarios.

## Impact

Successful implementation of reverse SSH tunnels allows attackers to maintain persistent access to an internal network, conduct lateral movement across subnets, and exfiltrate data while appearing as legitimate outbound traffic. This threat has been observed in campaigns leading to full domain compromise and ransomware deployment, posing a significant risk to enterprise infrastructure if left undetected.

## Recommendation

- Deploy the provided Sigma rule to identify unauthorized usage of OpenSSH and Plink with reverse forwarding arguments.
- Implement process creation logging via Sysmon (Event ID 1) or equivalent EDR telemetry to capture full command-line arguments for these binaries.
- Baseline legitimate administrative use of SSH/Plink within the environment; authorize specific service accounts or hosts that require these tools and alert on deviations.
- Review network egress logs for connections to non-standard or untrusted remote SSH servers originating from endpoints that should not be hosting external tunnels.
