---
title: Potential Proxy Execution via Systemd-run on Linux
slug: 2026-07-systemd-run-proxy-execution
description: This brief details how attackers may leverage the `systemd-run` utility on Linux systems for defense evasion and execution by running commands as detached, transient services or scopes to obscure their activities and parent-child process chains.
date: "2026-07-06T14:39:26Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - execution
  - linux
vendors:
  - Acronis
  - Amazon Web Services
  - BeyondTrust
  - Canonical
  - ClamAV
  - Debian
  - Elastic
  - Fortinet
  - GNOME
  - Google
  - Halcyon
  - Hexnode
  - Manjaro Development Team
  - Mozilla
  - Open Container Initiative
  - Palo Alto Networks
  - Picus Security
  - Plesk
  - QSetup
  - Rancher
  - Red Hat
  - Saltstack
  - SentinelOne
  - Slack
  - Tableau
  - Tychon
  - Vanta
  - VMware
  - Xfce
  - Zoom
products:
  - Acronis Cyber Protect
  - autorandr
  - AWS Replication Agent
  - BeyondTrust products
  - ClamScan
  - Debian Package Manager
  - DNF
  - Elephant
  - Firefox
  - FortiClient
  - GDM
  - GNOME Shell
  - Google Chrome
  - Google Cloud Agent
  - Google Cloud Linux Service
  - Halcyon Agent
  - Hexnode Agent
  - Hyprland
  - i3-zoom
  - K3s
  - K3s Server
  - Kubernetes
  - LXD
  - man-db
  - NGT Guest Agent
  - Pamac
  - Picus Updater
  - Plesk Task Manager
  - Ptyxis Agent
  - QSetup
  - RPM Package Manager
  - rpm-ostree
  - runc
  - Salt
  - Salt Minion
  - SentinelOne Agent
  - Slack
  - snapd
  - systemd
  - Tableau Server
  - Thunar
  - tmux
  - Tychon Endpoint
  - Vanta Launcher
  - xdg-desktop-portal
  - yay
  - Zoom
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This rule detects the execution of a command or binary through the systemd-run binary. Systemd-run can schedule commands to be executed in the background through systemd. Attackers may use this technique to execute commands while attempting to evade detection.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: An attacker might use systemd-run ... to execute commands while attempting to evade detection ... reducing visibility into the real payload and parent-child chain.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker might use systemd-run ... to start a shell, downloader, or credential-harvesting script in the background
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_proxy_execution_via_systemd_run.toml
rules:
  - title: Detect Potential Proxy Execution via Systemd-run
    description: Detects the execution of commands or binaries using `systemd-run`, a system utility that attackers may leverage to evade detection by running payloads as detached, transient services or scopes.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1218
      - T1574
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat brief outlines a technique where adversaries utilize the `systemd-run` binary on Linux systems for proxy execution, a method aimed at defense evasion and enabling command execution. `systemd-run` is a legitimate system utility designed to schedule commands for background execution through `systemd`. Attackers can exploit this functionality to run malicious payloads, such as shells, downloaders, or credential-harvesting scripts, as transient services or scopes. This technique allows them to detach their processes, obscure the direct parent-child relationships in the process tree, and mask their activities behind a trusted system utility, significantly reducing visibility for defenders. The technique can be used post-initial access to establish persistence, expand access, or facilitate data exfiltration without directly revealing the true malicious parent process.

## Attack Chain

1.  An attacker gains initial access to a Linux system, often via exploitation of a vulnerable service, compromised credentials, or a successful phishing attempt.
2.  After establishing a foothold, the attacker performs reconnaissance to understand the environment and identifies `systemd-run` as a potential tool for evading detection.
3.  The attacker stages a malicious payload (e.g., a reverse shell script, a downloader for additional malware, or a credential harvesting tool) onto the compromised system, possibly in a temporary directory.
4.  The attacker executes the malicious payload using `systemd-run`, typically with options like `--user` or `--scope`, to launch it as a transient systemd unit or scope, detaching it from the initiating process.
5.  `systemd-run` acts as a proxy, launching the malicious command or script in the background, making it appear as a legitimate systemd-managed process.
6.  The detached malicious payload executes, performing its intended actions such as establishing command and control, downloading further stages, escalating privileges, or exfiltrating data.
7.  The attacker might configure persistence mechanisms within the transient unit definition or by other means, ensuring continued access even after the initial session ends.

## Impact

If successful, attacks employing `systemd-run` for proxy execution can lead to significant compromises. Adversaries can execute arbitrary commands, establish covert persistence, download additional malicious tooling, or exfiltrate sensitive data without being easily detected through conventional process monitoring. The use of detached, transient units complicates forensic analysis and incident response by obfuscating the true origin and nature of the malicious processes. This can result in full system compromise, severe data breaches, unauthorized privilege escalation, or lateral movement across the network, making remediation challenging and prolonged.

## Recommendation

*   Deploy the Sigma rule "Detect Potential Proxy Execution via Systemd-run" in this brief to your SIEM and tune for your environment.
*   When triggered by the Sigma rule, reconstruct the full process tree around the `systemd-run` event to determine which user, shell, script, service, or remote access session invoked it.
*   Review the exact command passed through `systemd-run`, including flags such as `--user`, `--scope`, scheduling options, or custom unit names, to classify the spawned payload as expected or suspicious.
*   Isolate any affected Linux host from the network immediately, and terminate the malicious `systemd-run` transient unit or scope along with any child processes it launched.
*   Remove attacker persistence by deleting unauthorized unit files and drop-ins from `/etc/systemd/system/`, `/run/systemd/transient/`, `/var/lib/systemd/`, and affected users’ `~/.config/systemd/user/` directories.
