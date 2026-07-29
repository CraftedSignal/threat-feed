---
title: Detection of Container Tunneling and Port Forwarding Tools
slug: 2026-07-container-tunneling-detection
description: Elastic has released a detection rule for its Defend for Containers integration, identifying the use of tunneling and port forwarding tools within Linux containers, indicating potential threat actor activity such as command-and-control, data exfiltration, or lateral movement.
date: "2026-07-29T13:10:41Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - container-security
  - cloud-native
  - command-and-control
  - data-exfiltration
  - lateral-movement
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: This rule detects the use of tunneling and/or port forwarding tools inside a container. This could indicate a threat actor is using these tools to communicate with a C2 server.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: This rule detects the use of tunneling and/or port forwarding tools inside a container... A common pattern is running SSH with local/remote/dynamic forwarding or tools like chisel/socat to expose an internal service ... bypassing normal network controls and segmentation.
    confidence_band: high
references:
  - https://flare.io/learn/resources/blog/teampcp-cloud-native-ransomware
rules:
  - title: Tunneling and Port Forwarding Tools in Linux Containers
    description: Detects the execution of known tunneling and port forwarding tools like ssh, chisel, socat, gost, and ngrok within Linux containers, indicating potential command-and-control, data exfiltration, or lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1090
      - T1572
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Elastic has released a detection rule for its Defend for Containers integration, identifying the use of tunneling and port forwarding tools within Linux containers. These tools, including `ssh` with forwarding options, `chisel`, `socat`, `gost`, `ngrok`, and `proxychains`, are frequently employed by threat actors for establishing covert command-and-control (C2) channels, exfiltrating sensitive data from compromised environments, or achieving lateral movement within the container network. The rule, applicable to Elastic Stack version 9.3.0 and above, helps defenders identify malicious network relay activities that bypass conventional network controls and expose internal services, indicating a post-compromise phase or active exploitation within the containerized infrastructure.

## Attack Chain

1. An attacker gains initial access to a Linux container, typically through exploitation of a vulnerable application running within the container (e.g., CVE in a web application, misconfigured API).
2. The attacker deploys and executes a tunneling or port forwarding utility (such as `ssh` with `-L/-R/-D` flags, `chisel`, `socat`, `gost`, `ngrok`, `iodine`, or `proxychains`) from within the compromised container.
3. The tunneling tool establishes an encrypted or obfuscated connection from the container to an external, attacker-controlled command-and-control server, often bypassing firewall rules and network segmentation.
4. The established tunnel is then leveraged to access internal container network services, such as databases, API endpoints, or the Kubernetes API server, that would otherwise be inaccessible from the external network.
5. The attacker uses this internal access to move laterally to other containers, pods, or host nodes, and may attempt to establish persistence mechanisms within the compromised environment.
6. Sensitive data is exfiltrated through the covert channel, or the attacker gains broader control over the containerized infrastructure, potentially leading to disruption, ransomware deployment, or further exploitation.

## Impact

Successful exploitation involving tunneling and port forwarding in containers can lead to severe consequences. Attackers can bypass existing network security controls, facilitating covert command-and-control communications and exfiltration of sensitive data, including proprietary information, intellectual property, or customer records. Compromised containers can serve as pivot points for lateral movement across the entire containerized environment and potentially to the underlying host infrastructure. This can result in unauthorized access to critical internal systems, complete cluster takeover, deployment of additional malicious payloads (e.g., ransomware), and significant operational disruption.

## Recommendation

* Deploy the provided Sigma rule to your SIEM, ensuring `process_creation` logs from Linux containers are ingested with `container.id` enrichment.
* Investigate all alerts generated by the "Tunneling and Port Forwarding Tools in Linux Containers" rule by examining the full command line, process ancestry, and associated `container.id` to identify the owning workload and image.
* Correlate suspicious `process_creation` events involving tunneling tools with network telemetry (e.g., `network_connection` logs) to identify external C2 infrastructure and unexpected egress traffic.
* As part of incident response, isolate affected pods/containers immediately by scaling down workloads or applying deny-all egress policies to stop active tunnels.
* Capture and review command line arguments, parent processes, and established network connections from the affected container, specifically looking for `ssh -L/-R/-D`, `chisel client/server`, `socat TCP4-LISTEN`, and `ngrok` process patterns.
* Enforce image scanning and admission control policies to prevent the deployment of container images containing known tunneling utilities like `gost`, `iodine`, `dnscat`, `ssf`, `3proxy`, `wstunnel`, `pivotnacci`, `frps`, or `proxychains`.
