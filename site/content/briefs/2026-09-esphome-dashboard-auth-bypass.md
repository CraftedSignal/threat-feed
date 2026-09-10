---
title: Unauthenticated Access to ESPHome Dashboard via Ingress Interface Misconfiguration
slug: 2026-09-esphome-dashboard-auth-bypass
description: An auth bypass in the ESPHome Home Assistant add-on allows unauthenticated LAN access to the dashboard due to improper interface binding, enabling remote code execution on the host.
date: "2026-09-10T00:51:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:esphome:device-builder:*:*:*:*:*:*:*:*
tags:
  - auth-bypass
  - remote-code-execution
  - home-assistant
  - esphome
vendors:
  - ESPHome
products:
  - esphome-device-builder (< 1.0.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The add-on incorrectly bound the ingress site to all interfaces (0.0.0.0) instead of the loopback and supervisor gateway addresses.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: ESPHome's threat model documents that a dashboard caller can run arbitrary code at compile time and read or write files.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vv4j-m4vr-f3g6
  - https://github.com/esphome/device-builder/pull/1565
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade esphome-device-builder to 1.0.10
      owner: IT Operations
      due: 24h
      evidence: 'Fixed in device-builder 1.0.10 (PR #1565).'
  mitigation_plan:
    - priority: immediate
      action: Restrict ingress port access to supervisor and loopback IPs via host firewall.
      owner: IT Operations
      addresses: CVE-2026-59177
      evidence: Without upgrading, restrict access to the add-on's ingress port at the network layer.
---

The ESPHome device builder dashboard component for Home Assistant contains an authentication bypass vulnerability (CVE-2026-59177) that exposes an unauthenticated ingress site to the local network. The dashboard is designed to rely on the Home Assistant supervisor to provide authentication for ingress traffic. However, the add-on incorrectly bound the ingress site to all interfaces (0.0.0.0) instead of the loopback and supervisor gateway addresses.

Because the add-on operates in host network mode, this configuration exposes the dashboard directly to the host's LAN interface. Any device on the same local network as the Home Assistant host can access the dashboard without authentication. Given that the dashboard's capabilities include running arbitrary Python code and system shell commands, an attacker can leverage this exposure to gain full remote code execution on the Home Assistant host, including control over the configuration directory and managed ESPHome devices. The vulnerability was present by default in all host-network installs prior to version 1.0.10.

## Attack Chain

1. Attacker performs network discovery on the local area network to identify the Home Assistant host IP address.
2. Attacker probes the Home Assistant host on the known add-on ingress port to identify the ESPHome dashboard service.
3. Attacker sends an unauthenticated HTTP GET request to the ingress port, confirming access to the dashboard interface.
4. Attacker navigates the dashboard to the compile/validation section, which supports arbitrary code execution.
5. Attacker uploads a malicious ESPHome configuration file containing an `external_components` definition with embedded Python payloads.
6. Attacker triggers the dashboard compile function, causing the backend to execute the injected Python code or shell commands with the privileges of the Home Assistant add-on process.
7. Attacker achieves persistent access or full system control by deploying a reverse shell or modifying the Home Assistant configuration files.

## Impact

Successful exploitation results in full compromise of the Home Assistant add-on and the underlying host. The attacker gains the ability to read or modify arbitrary files within the mounted configuration and data directories, and can execute system-level commands. This vulnerability affects any Home Assistant instance running the host-networked ESPHome add-on, posing a critical risk to users on shared or untrusted local networks.

## Recommendation

Prioritized actions for security and infrastructure teams:
- Immediately upgrade the `esphome` container to include `esphome-device-builder` version 1.0.10 or later.
- Implement network-layer access control on the Home Assistant host to restrict access to the ESPHome ingress port, ensuring only the local loopback and the supervisor gateway (172.30.32.1) are permitted.
- Audit the Home Assistant configuration directory for unauthorized modifications or newly created files that may indicate previous exploitation of this interface.
- Segment the Home Assistant host from untrusted IoT devices or guest network segments to mitigate the risk of unauthorized local network access.
