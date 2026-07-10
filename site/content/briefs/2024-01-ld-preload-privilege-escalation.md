---
title: Linux Privilege Escalation via LD_PRELOAD Shared Object Modification
slug: 2024-01-ld-preload-privilege-escalation
description: Attackers can exploit the LD_PRELOAD environment variable on Linux systems to inject malicious shared objects into privileged processes, leading to arbitrary code execution and privilege escalation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - ld_preload
  - linux
vendors:
  - Linux
products:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_ld_preload_shared_object_modif.toml
rules:
  - title: Detect LD_PRELOAD Usage with setuid/setgid
    description: Detects the usage of LD_PRELOAD environment variable when executing setuid or setgid binaries, which can be indicative of privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Shared Object Loading via LD_PRELOAD
    description: Detects when a shared object is loaded via LD_PRELOAD from a suspicious location (e.g., /tmp).
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - image_load
      - linux
rules_count: 2
---

The LD_PRELOAD environment variable in Linux allows users to specify shared libraries that should be loaded before others when a program is executed. This functionality, while legitimate, can be abused by attackers to inject malicious code into processes, including those running with elevated privileges (e.g., setuid binaries). By crafting a malicious shared object and setting LD_PRELOAD to point to it, an attacker can hijack the execution flow of a vulnerable program. This technique is effective because the preloaded library's code will be executed before the main program's code. This can lead to complete system compromise if the hijacked process runs as root.

## Attack Chain

1.  The attacker identifies a setuid binary vulnerable to LD_PRELOAD exploitation.
2.  The attacker creates a malicious shared object (e.g., `evil.so`) containing code to escalate privileges, such as creating a new setuid root shell.
3.  The attacker sets the `LD_PRELOAD` environment variable to the path of the malicious shared object: `export LD_PRELOAD=/tmp/evil.so`.
4.  The attacker executes the vulnerable setuid binary.
5.  The dynamic linker (`ld-linux.so`) loads the malicious shared object specified by `LD_PRELOAD` into the process's memory space before the intended libraries.
6.  The malicious shared object's constructor function (e.g., `_init()`) is executed, which performs actions like creating a new setuid root shell or modifying system files.
7.  The original setuid binary continues execution (if the attacker hasn't completely taken over).
8.  The attacker uses the newly created setuid root shell or modified system to gain complete control over the system.

## Impact

Successful exploitation via LD_PRELOAD allows an attacker to gain root privileges on the affected Linux system. This allows them to read sensitive data, install malware, modify system configurations, and potentially use the compromised system as a staging point for lateral movement within a network. The scope of the impact depends on the attacker's objectives, but privilege escalation always leads to a severe breach of system security.

## Recommendation

*   Monitor for the execution of setuid/setgid binaries with `LD_PRELOAD` set (see Sigma rule "Detect LD_PRELOAD Usage with setuid/setgid").
*   Implement file integrity monitoring for system binaries and libraries to detect unauthorized modifications (implement using file_event logs).
*   Restrict the use of `LD_PRELOAD` where possible, especially for privileged processes.
*   Audit setuid/setgid binaries for vulnerabilities that could be exploited via `LD_PRELOAD`.
*   Deploy the Sigma rule "Detect Suspicious Shared Object Loading via LD_PRELOAD" to identify potential malicious library injections.
