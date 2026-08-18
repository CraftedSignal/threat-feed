---
title: MacSync Stealer Behavioral Hunting and Infrastructure Analysis
slug: 2026-08-macsync-stealer
description: MacSync Stealer is a macOS-based information stealer that evades detection through rapid domain rotation while maintaining consistent behavioral pivots in its payload retrieval, C2 communication, and chunked exfiltration patterns.
date: "2026-08-18T20:50:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - macos
  - stealer
  - information-stealer
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Execution began from an interactive shell session consistent with ClickFix social engineering, where users are tricked into pasting or running commands in Terminal.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: After execution, the malware communicated with attacker-controlled infrastructure using recurring URI paths, macOS User-Agent strings, API-key headers, and curl command-line options.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Collected data was staged under temporary paths, compressed into an archive, split into chunks, and uploaded through HTTP PUT requests using curl with the --data-binary argument.
    confidence_band: high
rules:
  - title: Detect MacSync Stealer Exfiltration via Curl
    description: Detects MacSync Stealer chunked data exfiltration using curl with specific HTTP PUT parameters and data-binary flags
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection for curl-based exfiltration
      owner: Detection Engineering
      due: 24h
      evidence: Source documents curl-based exfiltration as a consistent behavioral pivot
  hunt_leads:
    - lead: Search for processes invoking curl with --data-binary or -X PUT
      technique_id: T1041
      data_needed:
        - Process Command Line
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Microsoft identified chunked HTTP PUT uploads as a durable behavioral pivot
---

MacSync Stealer is an information-stealing malware specifically targeting macOS environments. First identified by RST Cloud, the malware is notable for its use of rapidly rotating command-and-control (C2) infrastructure to evade static domain-based detection. Microsoft Defender Experts expanded the understanding of this threat by correlating recurring endpoint and network behaviors, uncovering more than 30 related domains. The malware typically initiates via ClickFix social engineering, where users are manipulated into executing malicious shell commands in Terminal. Once active, the stealer exhibits durable behavioral traits - including specific URI paths, curl command-line arguments, and unique HTTP header parameters - that persist regardless of the underlying domain. These patterns support a full lifecycle of collection, staging, and exfiltration of sensitive macOS data, including Keychain material, browser credentials, and SSH keys.

## Attack Chain

1. Initial access is achieved via ClickFix social engineering, prompting the user to paste and execute malicious commands in a Terminal session.
2. The interactive shell session invokes `curl` to fetch the primary payload from attacker-controlled infrastructure using paths containing `/curl/`.
3. The malware performs C2 check-ins using `curl` with consistent flags (`-k`, `-s`, `--max-time`), specific macOS User-Agent strings, and a static `api-key` header.
4. The stealer performs local discovery to identify Keychain files, browser profile data, cloud credentials, and SSH keys stored in user directories.
5. Collected sensitive data is moved to temporary directories and compressed into a single archive file.
6. The archive is split into smaller chunks, which are exfiltrated using `curl` via HTTP PUT requests with the `--data-binary` flag.
7. Exfiltration traffic is identified by unique URL parameters including `upload_id`, `chunk_index`, and `total_chunks` mapped to `/gate?buildtxd=` URI patterns.
8. Final cleanup occurs as the malware deletes temporary staging folders, compressed archives, and associated lock files to minimize forensic artifacts.

## Impact

MacSync Stealer poses a high risk to macOS users by facilitating the theft of high-value credentials, including browser-stored logins, cloud service tokens, and SSH keys. If the attack succeeds, attackers gain persistent unauthorized access to the victim's digital accounts and local development environments. While specific victim counts are not disclosed, the threat's capability to exfiltrate vast amounts of sensitive local data makes it a significant risk to individuals and enterprise users on the macOS platform.

## Recommendation

* Deploy the Sigma rule below to detect execution of `curl` commands containing known MacSync Stealer URI patterns and command-line flags.
* Monitor process execution logs for `curl` sessions that utilize the `--data-binary` flag in conjunction with `PUT` requests, as these are highly indicative of exfiltration.
* Implement endpoint controls to restrict the execution of untrusted commands in Terminal, specifically monitoring for base64-encoded or obfuscated script injection characteristic of ClickFix campaigns.
* Configure network monitoring to alert on HTTP headers containing the `api-key` string when used in conjunction with macOS User-Agent strings in non-standard environments.
