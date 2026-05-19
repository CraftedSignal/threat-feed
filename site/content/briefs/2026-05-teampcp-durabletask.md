---
title: TeamPCP Compromises PyPi Package durabletask
slug: 2026-05-teampcp-durabletask
description: TeamPCP compromised the PyPi package durabletask (versions 1.4.1, 1.4.2, and 1.4.3), stealing credentials for AWS, Azure, GCP, K8s, and Vault, brute-forcing passwords from password managers, and exfiltrating shell history before propagating to up to 5 targets via AWS SSM and Kubernetes.
date: "2026-05-19T18:21:44Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - credential-theft
  - pypi
vendors:
  - Microsoft
products:
  - durabletask (1.4.1)
  - durabletask (1.4.2)
  - durabletask (1.4.3)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.wiz.io/blog/durabletask-teampcp-supply-chain-attack
iocs:
  - type: domain
    value: check.git-service.com
  - type: domain
    value: t.m-kosche.com
  - type: url
    value: https://check.git-service[.]com/rope.pyz
  - type: url
    value: https://t.m-kosche[.]com/rope.pyz
  - type: ip
    value: 83.142.209.194
  - type: hash_sha256
    value: 069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce
  - type: hash_sha256
    value: 7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8
  - type: hash_sha256
    value: aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5
  - type: hash_sha256
    value: 877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec
  - type: filepath
    value: /tmp/managed.pyz
  - type: filepath
    value: /tmp/rope-*.pyz
  - type: filepath
    value: ~/.cache/.sys-update-check
  - type: filepath
    value: ~/.cache/.sys-update-check-k8s
  - type: filepath
    value: /tmp/.rope_state/ssm_instances.json
ioc_counts:
  domain: 2
  filepath: 5
  hash_sha256: 4
  ip: 1
  url: 2
rules:
  - title: Detect Suspicious Python Payload Execution
    description: Detects execution of the downloaded python payload from durabletask supply chain attack
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect infection marker
    description: Detects creation of the infection marker file
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On May 19, 2026, Wiz reported that TeamPCP compromised the official Microsoft Python client for the Durable Task workflow execution framework, durabletask, specifically versions 1.4.1, 1.4.2, and 1.4.3. This supply chain attack involves a malicious payload similar to previous TeamPCP compromises. Upon execution, the payload targets a wide array of cloud credentials including those for AWS, Azure, GCP, Kubernetes, and Vault. It also attempts to brute-force passwords stored in Bitwarden, 1Password, and pass/gopass, and exfiltrates sensitive shell history files. This campaign matters because it allows attackers to gain unauthorized access to cloud infrastructure, escalate privileges, and potentially compromise entire environments. The worm can propagate to up to 5 targets per infected host.

## Attack Chain

1. A developer or system administrator installs a compromised version (1.4.1, 1.4.2, or 1.4.3) of the `durabletask` PyPi package.
2. The compromised package executes malicious code from `__init__.py` or `task.py` (depending on the durabletask version) which downloads a payload, either `transformers.pyz` or `rope.pyz`, to `/tmp/managed.pyz` or `/tmp/rope-*.pyz`.
3. A Python interpreter executes the downloaded payload using `python3 /tmp/managed.pyz`.
4. The `managed.pyz` payload attempts to steal credentials for AWS, Azure, GCP, Kubernetes, and Vault, as well as passwords stored in Bitwarden, 1Password, and pass/gopass.
5. The payload also attempts to brute-force unlock password managers using harvested passwords from environment variables and shell history (.bash_history, .zsh_history).
6. The payload exfiltrates collected credentials and shell history to the C2 server via endpoints like `/api/public/version`.
7. The malware attempts to propagate laterally to other systems (up to 5 targets per host) via AWS SSM (using `SSM:SendCommand` and `SSM:DescribeInstanceInformation`) and Kubernetes (using `kubectl exec`).
8. Persistence is established by creating an infection marker file, either `~/.cache/.sys-update-check` (AWS/general) or `~/.cache/.sys-update-check-k8s` (Kubernetes).

## Impact

This supply chain attack allows TeamPCP to steal sensitive credentials for major cloud platforms (AWS, Azure, GCP), container orchestration systems (Kubernetes), and secrets management tools (Vault). The attackers also attempt to compromise password managers, and exfiltrate shell history for further reconnaissance. The malware propagates laterally to up to 5 targets per infected host, potentially leading to widespread compromise within an organization's cloud infrastructure. Success allows the attackers to steal data, escalate privileges, and deploy ransomware.

## Recommendation

*   Search lockfiles and CI logs for `durabletask` versions 1.4.1, 1.4.2, or 1.4.3 to identify potential exposure.
*   Look for `/tmp/managed.pyz` or `/tmp/rope-*.pyz` on Linux systems as indicators of downloaded payloads (IOC filepath).
*   Search for the infection marker `~/.cache/.sys-update-check` or `~/.cache/.sys-update-check-k8s` on affected systems to confirm payload execution (IOC filepath).
*   Block the C2 domains `check.git-service.com` and `t.m-kosche.com` at the DNS/proxy level (IOC domain).
*   Monitor process creation events for `python3 /tmp/managed.pyz` to identify running malicious payloads, and deploy the Sigma rule provided below (rule: `Detect Suspicious Python Payload Execution`).
*   Monitor network connections for outbound traffic to the exfil endpoints `/v1/models`, `/audio.mp3`, and `/api/public/version` (IOC url).
