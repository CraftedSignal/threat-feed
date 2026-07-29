---
title: Suspicious Process Execution in Containers from Transient Directories
slug: 2026-07-suspicious-container-exec
description: Adversaries exploit containerized environments by executing malicious code or interactive shells from transient, low-trust directories like /tmp or /dev/shm, or using executables with hidden names, to evade detection, establish persistence, and facilitate data exfiltration.
date: "2026-07-29T12:36:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container-security
  - cloud-native
  - kubernetes
  - linux
  - defense-evasion
  - execution
  - command-and-control
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Adversaries may use these directories to execute malicious code or exfiltrate data. This behavior signals live operator control and attempts to evade forensics and policy controls. By using transient directories and interactive execution, the attacker evades traditional forensic analysis and image-based security controls.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A frequent pattern is an attacker gaining a shell via kubectl exec, fetching a static reverse shell or tunneling tool into /dev/shm or /tmp, and running it interactively to pivot or siphon data.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1620
    technique_name: Reflective Code Loading
    evidence: The attacker might load and execute code from memory-backed filesystems like /dev/shm, described as a location where a 'static reverse shell or tunneling tool' might be fetched and run interactively.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Capture live network activity from the container to spot external callbacks, tunnels, or exfil destinations, and isolate the pod if suspicious connections are present.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/defense_evasion_interactive_process_execution_from_suspicious_directory.toml
rules:
  - title: Suspicious Process Execution in Containers from Transient Directories
    description: Detects process execution within a Linux container where the executable path is located in a suspicious, transient directory (/tmp, /dev/shm, etc.) or if the executable's basename starts with a dot (hidden file), indicating potential adversary activity and defense evasion. This rule targets behaviors common in post-exploitation container environments.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1071
      - T1564
      - T1564.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat brief details a technique where adversaries, having gained initial access to a container, leverage transient or low-trust directories such as `/tmp`, `/dev/shm`, `/var/tmp`, `/run`, `/var/run`, `/mnt`, `/media`, and `/boot` to stage and execute malicious payloads. This approach is primarily used to evade detection, establish persistence, and prepare for data exfiltration or further pivoting within the environment. Attackers often gain a shell via methods like `kubectl exec`, then download or copy tools (e.g., reverse shells, tunneling utilities) into these volatile directories, executing them interactively. By utilizing locations outside the container's image filesystem, they circumvent image-based security controls and complicate forensic analysis, signalling live operator control and attempts to bypass policy.

## Attack Chain

1. **Initial Access**: An adversary gains a shell into a container, potentially via a compromised application vulnerability, misconfigured API, or through mechanisms like `kubectl exec` or `attach` into a running pod.
2. **Staging Malicious Tools**: The attacker uploads or downloads malicious binaries, scripts, or tools (e.g., static reverse shells, tunneling tools) into transient or low-trust directories within the compromised container, such as `/tmp`, `/dev/shm`, or `/var/tmp`.
3. **Execution from Suspicious Directory**: The adversary executes these staged malicious tools or interactive shells directly from these transient directories. This avoids writing to the immutable parts of the container image, making detection and forensic analysis more challenging.
4. **Defense Evasion**: By leveraging volatile storage locations and interactive execution, the attacker evades traditional image-based security controls and potentially established forensic collection mechanisms designed for persistent storage.
5. **Command and Control (C2)**: The executed malicious tools establish C2 communication, often involving external callbacks or tunnels, to an attacker-controlled infrastructure for remote management and further instructions.
6. **Data Exfiltration / Impact**: The attacker uses the established access to pivot within the environment, siphon sensitive data, establish persistence, or perform other malicious actions that may lead to further compromise or impact on the host system or other containers.

## Impact

Successful exploitation allows adversaries to maintain live operator control over compromised containers, enabling data theft and potentially pivoting to other parts of the cloud or Kubernetes environment. This technique facilitates evasion of forensic analysis and policy controls, leading to prolonged presence and unchecked malicious activities. Specific risks include exfiltration of sensitive data, establishment of persistence on the host or in other containers, and privileged access if the affected pod has elevated permissions or host namespace access, potentially leading to full cluster compromise. Uncontained threats can allow writes to critical system directories like `/boot` or exposure of credentials.

## Recommendation

* Deploy the Sigma rule in this brief to your SIEM and tune for your environment, paying particular attention to process creation logs for Linux containers.
* Review Kubernetes API server audit logs for `pod/exec` or `attach` events around any alert, correlating them with the initiating user, source IP, and service account to identify the initial access vector.
* Harden Kubernetes deployments by enforcing `readOnlyRootFilesystem` with `seccomp` and `AppArmor`, and mounting `/tmp` and `/dev/shm` with `noexec`, `nodev`, `nosuid` flags where appropriate to restrict execution from these paths.
* Use admission policies to allowlist executable paths within containers and deny interactive TTYs for production workloads, preventing unauthorized process execution.
* Implement NetworkPolicies to apply deny-all egress rules by default for production pods, then explicitly allow only necessary outbound connections to prevent C2 and data exfiltration.
