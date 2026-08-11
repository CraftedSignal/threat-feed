---
title: Kimwolf v7 Botnet Evolution and Android IoT Targeting
slug: 2026-08-kimwolf-v7
description: Kimwolf v7 is an evolved Android/IoT botnet that leverages unauthenticated ADB access, Ethereum Name Service (ENS) resolution, and HTTP/2 browser fingerprinting to perform resilient DDoS operations.
date: "2026-08-11T10:25:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - iot
  - botnet
  - android
  - ddos
products:
  - Android TV box
  - Android set-top box
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1590.001
    technique_name: Gather Victim Network Information
    evidence: Kimwolf spreads by misusing residential proxy services to reach unauthenticated Android Debug Bridge (ADB) instances on local networks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The malware masks its process name as netd_service to blend in with legitimate Android system processes.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
    evidence: Kimwolf v7 adds an HTTP/2-based DDoS flood that constructs complete browser fingerprints.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573.001
    technique_name: 'Encrypted Channel: Symmetric Cryptography'
    evidence: The malware statically links BoringSSL for Transport Layer Security (TLS) operations.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498.002
    technique_name: 'Network Denial of Service: HTTP Flood'
    evidence: One of the most notable new capabilities in Kimwolf v7 is an HTTP/2 flood powered by the nghttp2 library.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
iocs:
  - type: domain
    value: eth.rpcuniverse.com
  - type: domain
    value: edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion
  - type: ip
    value: 212.193.31.119
  - type: ip
    value: 212.193.31.122
  - type: ip
    value: 212.193.31.158
ioc_counts:
  domain: 2
  ip: 3
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block known Kimwolf C2 IP addresses in firewall
      owner: SOC
      due: 24h
      evidence: Source lists malicious IPs under C2 infrastructure
  mitigation_plan:
    - priority: immediate
      action: Disable ADB on all corporate-managed Android IoT devices
      owner: IT Operations
      addresses: Unauthenticated ADB access
      evidence: Malware spreads by misusing ADB on local networks
---

Kimwolf v7 is the latest iteration of the Kimwolf (or AISURU) botnet, which specifically targets Android-based IoT devices such as TV boxes and set-top boxes. First identified in February 2026, this variant represents a significant hardening of the botnet's command-and-control (C2) and offensive capabilities. Kimwolf v7 utilizes the nghttp2 library to construct full browser fingerprints within HTTP/2 DDoS floods, making the traffic harder to distinguish from legitimate user activity.

The botnet exhibits high resilience to takedowns by utilizing a multi-tier C2 infrastructure. This includes querying five hard-coded public Ethereum RPC endpoints to resolve C2 addresses via Ethereum Name Service (ENS), an operator-controlled RPC facade (eth.rpcuniverse.com), and a hard-coded Tor .onion hidden service as a secondary fallback. The malware employs a local proxy architecture to route traffic across both clearnet and Tor. The binary masks its process name as 'netd_service' to evade detection on compromised Android systems.

## Attack Chain

1. The botnet scans for unauthenticated Android Debug Bridge (ADB) ports (5555) on local networks, often utilizing residential proxy services to reach target devices.
2. The malware is installed onto the device via the ADB session without requiring user authentication.
3. Upon execution, the binary renames its process to 'netd_service' to masquerade as a legitimate Android system daemon.
4. The bot checks for its presence using a Unix domain socket '@n[redacted]boxv7' to ensure only a single instance remains active.
5. The bot initiates C2 resolution by querying hard-coded public Ethereum RPC endpoints to resolve ENS domain records.
6. If public resolution fails, the binary initiates a proxy state machine to connect to its hard-coded Tor hidden service.
7. The bot maintains persistence through local boot receivers and awaits commands to initiate HTTP/2 DDoS floods or other malicious tasks.
8. During DDoS operations, the malware crafts HTTP/2 headers using spoofed browser fingerprints to evade rate-limiting and detection systems.

## Impact

Kimwolf v7 primarily affects Android TV and set-top boxes, turning them into components of a high-resilience botnet used for large-scale DDoS attacks. The use of spoofed browser fingerprints increases the risk of successful traffic mitigation bypass, potentially overwhelming target services and causing significant infrastructure downtime. The botnet's reliance on residential proxy misuse also facilitates widespread, low-effort distribution across diverse networks.

## Recommendation

* Audit all Android TV and set-top box devices on the network to ensure the Android Debug Bridge (ADB) is disabled on port 5555.
* Monitor internal network traffic for unusual connections to public Ethereum RPC endpoints, particularly those attempting to resolve ENS-related queries from IoT/Android devices.
* Block or alert on connections to the known Tor hidden service: edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion.
* Implement egress filtering for known C2 infrastructure IPs associated with the Kimwolf botnet, such as the 212.193.31.0/24 range.
* Deploy endpoint security monitoring to detect process masquerading, specifically processes naming themselves 'netd_service' that were not spawned by the system init process.
