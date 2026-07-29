---
title: Curl SOCKS Proxy Detected via Elastic Defend for Containers
slug: 2026-07-curl-socks-proxy-container
description: Attackers utilize the `curl` command-line tool with SOCKS proxy options inside Linux containers to bypass network restrictions, enabling command and control communications or data exfiltration, which defenders can detect by monitoring process execution within container environments for suspicious `curl` arguments and network tunneling activity.
date: "2026-07-29T12:28:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - linux
  - command-and-control
  - threat-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: This detection flags curl invocations inside Linux containers that use SOCKS proxy options, indicating traffic tunneling to evade egress controls and enable data exfiltration or C2 communications.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: This detection flags curl invocations inside Linux containers that use SOCKS proxy options, indicating traffic tunneling to evade egress controls and enable data exfiltration or C2 communications.
    confidence_band: high
references:
  - https://www.trendmicro.com/en_us/research/25/f/tor-enabled-docker-exploit.html
rules:
  - title: Detect Curl SOCKS Proxy Usage in Linux Containers
    description: Detects the use of the 'curl' command-line tool with SOCKS proxy options inside Linux containers, indicating potential command and control or data exfiltration.
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

This threat brief details the use of the `curl` command-line tool with SOCKS proxy options within Linux container environments by attackers. This technique is employed to establish covert communication channels, bypass network egress filtering, facilitate data exfiltration, or maintain command and control (C2) over compromised systems. The detection, provided by Elastic Defend for Containers, focuses on identifying `curl` invocations that include specific arguments such as `--socks5-hostname`, `--proxy`, `--preproxy`, or `-x` combined with a SOCKS prefix. This activity signifies an operator, having gained initial shell access to a container, is attempting to tunnel traffic to external endpoints, fetch additional payloads, or transmit stolen data through an established SOCKS proxy, potentially set up via precursor tools like `ssh -D`, `chisel`, or `tor`.

## Attack Chain

1. **Initial Access**: An attacker gains initial access to a Linux container, typically through a vulnerable application, misconfiguration, or stolen credentials, leading to shell access within the container.
2. **Environment Reconnaissance**: The attacker performs reconnaissance within the compromised container to identify network capabilities, installed tools, and potential egress paths.
3. **Tunneling Setup**: The attacker deploys and configures a tunneling tool, such as `ssh -D`, `chisel`, `cloudflared`, `tor`, or `3proxy`, to establish a SOCKS proxy listener within the container or on the host.
4. **Local Proxy Establishment**: The chosen tunneling mechanism creates a local SOCKS proxy, often listening on `localhost` (e.g., `localhost:1080`), to facilitate redirected network traffic.
5. **Malicious `curl` Execution**: The attacker executes the `curl` command from within the container, explicitly directing it to use the locally established SOCKS proxy via options like `-x socks5h://localhost:1080` or `--socks5-hostname`.
6. **External C2 Communication**: `curl` then uses the SOCKS tunnel to communicate with external command and control (C2) servers, receiving further instructions or sending beaconing traffic.
7. **Data Exfiltration**: The attacker utilizes `curl` with data transfer options (`-d/--data`, `-T/--upload-file`) to exfiltrate sensitive data from the compromised container through the SOCKS tunnel to an attacker-controlled destination.
8. **Payload Fetching**: `curl` may also be used to download additional malicious tools or payloads from external repositories via the SOCKS proxy, extending the attacker's presence and capabilities.

## Impact

Successful exploitation allows attackers to bypass network egress controls, establish persistent command and control channels, and exfiltrate sensitive data from compromised Linux container environments. This can lead to significant data breaches, further compromise of the underlying host or other containers, and disruption of critical services. While no specific victim counts or sectors are provided, the impact can be severe for any organization heavily relying on containerized applications, as it undermines their network segmentation and security controls.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
* Ensure Elastic Defend for Containers is enabled and configured to collect process execution logs from your Linux container environments, including `process.name` and `process.args` fields.
* Investigate alerts from the `Detect Curl SOCKS Proxy Usage in Linux Containers` rule by retrieving the full `curl` command line, identifying the SOCKS proxy host and port, and analyzing target URLs for reputation.
* Examine process ancestry and related Kubernetes metadata (pod, namespace, service account, node, image) for processes identified by the `Detect Curl SOCKS Proxy Usage in Linux Containers` rule to attribute the activity to a specific user or application.
* Review network flows and DNS queries originating from containers flagged by the `Detect Curl SOCKS Proxy Usage in Linux Containers` rule, especially traffic traversing the identified SOCKS proxy, to quantify data volume and assess destination reputation.
