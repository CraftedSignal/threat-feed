---
title: Dynamic Linker Modification for Defense Evasion and Privilege Escalation in Linux Containers
slug: 2026-07-dynamic-linker-hijacking-container
description: Adversaries modify the dynamic linker preload shared object (`/etc/ld.so.preload`) or configuration files (`/etc/ld.so.conf.d/*`, `/etc/ld.so.conf`) inside Linux containers to hijack the dynamic linker, forcing the system to load malicious libraries at runtime, thereby gaining unauthorized access, maintaining persistence, escalating privileges, and evading detection of malicious processes.
date: "2026-07-29T12:37:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - persistence
  - privilege-escalation
  - linux
  - container
  - threat-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Adversaries may hijack the dynamic linker by modifying the /etc/ld.so.preload file to point to malicious libraries. This behavior can be used to grant unauthorized access to system resources and has been used to evade detection of malicious processes in container environments.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Adversaries may hijack the dynamic linker by modifying the /etc/ld.so.preload file to point to malicious libraries. This behavior can be used to grant unauthorized access to system resources and has been used to evade detection of malicious processes in container environments.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Adversaries may hijack the dynamic linker by modifying the /etc/ld.so.preload file to point to malicious libraries. This behavior can be used to grant unauthorized access to system resources and has been used to evade detection of malicious processes in container environments.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/
  - https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang/
  - https://sysdig.com/blog/threat-detection-aws-cloud-containers/
rules:
  - title: Detect Dynamic Linker Modification in Linux Containers
    description: Detects the creation or modification of dynamic linker preload or configuration files (`/etc/ld.so.preload`, `/etc/ld.so.conf`, or files within `/etc/ld.so.conf.d/`) inside Linux containers, which is a common technique for defense evasion, persistence, and privilege escalation by hijacking execution flow.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1574
      - T1574.006
    data_sources:
      - file_event
      - linux
rules_count: 1
---

This threat brief details a technique where adversaries manipulate the Linux dynamic linker within containerized environments to achieve defense evasion, persistence, and privilege escalation. Discovered and monitored by Elastic's Cloud Defend, this technique involves modifying critical system files like `/etc/ld.so.preload`, `/etc/ld.so.conf.d/*`, or `/etc/ld.so.conf`. By altering these files, attackers can direct the system to load malicious shared libraries before legitimate ones, effectively hijacking execution flow. This allows for unauthorized access to system resources and helps malicious processes remain undetected. This behavior has been observed in various malware campaigns, including those by the TeamTNT group utilizing Hildegard malware and the Rocke group, highlighting its effectiveness in container compromise. The detection rule specifically targets the creation or modification of these files within Linux containers.

## Attack Chain

1. An adversary gains initial access to a vulnerable Linux container environment through various methods (e.g., exposed services, vulnerable applications, misconfigurations).
2. The adversary identifies a writable location for a malicious shared object (`.so`) library within the container's filesystem.
3. The adversary deploys a custom malicious shared library designed to hook legitimate system calls or perform arbitrary code execution.
4. The adversary modifies `/etc/ld.so.preload` or a file within `/etc/ld.so.conf.d/` or `/etc/ld.so.conf` to reference the path of the malicious shared library.
5. Upon the next execution of any new process within the affected container, the dynamic linker (`ld.so`) loads the malicious library specified in the preload configuration before other libraries.
6. The malicious library executes its payload, which can include unauthorized access to system resources, maintaining persistence, escalating privileges, or hindering security tools by evading detection.
7. The attacker leverages the compromised dynamic linker to control the container, exfiltrate data, or launch further attacks.

## Impact

Successful exploitation of this technique can lead to severe consequences within containerized environments. Adversaries gain unauthorized access to system resources, allowing them to execute arbitrary code, bypass security controls, and establish persistence. This can lead to full compromise of the container, enabling data exfiltration, cryptomining, or pivoting to other systems within the network. The ability to evade detection means that malicious activities can remain undiscovered for longer periods, increasing the risk of widespread compromise. Organizations using Linux containers without robust monitoring for file integrity of dynamic linker configurations are particularly vulnerable.

## Recommendation

* Deploy the Sigma rule in this brief to your SIEM to detect suspicious modifications to dynamic linker configuration files within containers.
* Ensure `file_event` logging is enabled for Linux systems, particularly within container environments, to capture modifications to critical system files like `/etc/ld.so.preload`, `/etc/ld.so.conf.d/*`, and `/etc/ld.so.conf`.
* Review container images and configurations to minimize potential vulnerabilities that could lead to initial access.
* Implement file integrity monitoring (FIM) for sensitive files within containers, especially those related to system loaders, to detect unauthorized changes.
* Regularly audit and restrict write permissions to system directories and configuration files within containers to prevent unauthorized modification of dynamic linker files.
