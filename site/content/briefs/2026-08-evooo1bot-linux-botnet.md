---
title: Evooo1Bot Modular Linux Botnet
slug: 2026-08-evooo1bot-linux-botnet
description: Evooo1Bot is a modular Linux-based botnet that targets internet-facing devices to perform DDoS attacks, SSH brute-forcing, vulnerability exploitation, and SOCKS proxy relay operations.
date: "2026-08-13T14:22:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - botnet
  - linux
  - ddos
  - ssh-brute-force
  - proxy
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Evooo1Bot ... targets internet-facing devices ... with CVE exploits
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The malware is a Linux-based botnet capable of executing commands on compromised devices.
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.004
    technique_name: 'Remote Services: SSH'
    evidence: The botnet performs brute-force SSH credential attacks.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Evooo1Bot ... executes distributed denial-of-service (DDoS) attacks.
    confidence_band: high
references:
  - https://feeds.fortinet.com/~/967797734/0/fortinet/blog/threat-research~MultiFunctional-Linux-Botnet-%e2%80%9cEvoooBot%e2%80%9d
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify high-volume outbound connections from Linux infrastructure to unknown destinations.
      technique_id: T1021.004
      data_needed:
        - NetFlow / IPFIX
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Botnet uses infected hosts as SOCKS relays.
  mitigation_plan:
    - priority: medium_term
      action: Enforce SSH key-based authentication and disable password login.
      owner: IT Operations
      addresses: SSH Brute Force
      evidence: Botnet performs brute-force SSH attacks.
---

Evooo1Bot is a newly analyzed modular Linux-based botnet identified by FortiGuard Labs. The threat actor leverages this malware to compromise internet-facing devices, converting them into active nodes within a botnet infrastructure. The botnet is notable for its multi-functional design, which supports a variety of malicious activities including distributed denial-of-service (DDoS) attacks, automated brute-force attempts against SSH services, the exploitation of known vulnerabilities to achieve initial access, and the utilization of infected hosts as SOCKS proxy relays to mask and redirect malicious traffic. This botnet targets a broad range of Linux-based devices, emphasizing the need for robust hardening of perimeter-facing services and strong credential management for administrative interfaces.

## Impact

Successful compromise by Evooo1Bot results in the loss of device integrity, the potential for unauthorized network transit via SOCKS proxying, and the use of the device as a participant in wider DDoS attacks. The scope of impact includes potential service disruption, unauthorized access to internal resources, and increased risk of follow-on attacks originating from the local network.

## Recommendation

Detection engineering teams should focus on identifying unauthorized administrative access attempts and anomalous network traffic associated with SOCKS proxies.
* Implement monitoring for repeated failed SSH login attempts from diverse external IP addresses.
* Baseline network traffic for high volumes of outbound connections on common proxy ports.
* Audit internet-facing devices to ensure that all services are patched against known remote code execution vulnerabilities.
* Restrict inbound SSH access to required management jump hosts or use multi-factor authentication for all remote access.
