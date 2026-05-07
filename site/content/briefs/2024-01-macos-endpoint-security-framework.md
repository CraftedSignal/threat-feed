---
title: Leveraging Apple's Endpoint Security Framework for Process Monitoring
slug: 2024-01-macos-endpoint-security-framework
description: This brief discusses the use of Apple's Endpoint Security Framework in macOS 10.15 and later for user-mode process monitoring, offering improved capabilities over the older OpenBSM subsystem.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - macos
  - endpoint-security
  - process-monitoring
  - defense-evasion
  - discovery
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS 10.15 (Catalina)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1057
    technique_name: Process Discovery
references:
  - https://objective-see.org/blog/blog_0x47.html
rules:
  - title: Detect Process Execution via Endpoint Security Framework
    description: Detects process execution events using Apple's Endpoint Security Framework. This can help identify suspicious or malicious processes being launched on the system.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - macos
  - title: Detect Endpoint Security Client Initialization Error - Missing Entitlement
    description: Detects attempts to initialize an Endpoint Security client without the required entitlement (com.apple.developer.endpoint-security.client). This can indicate unauthorized attempts to leverage the framework.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

This document explores the use of Apple's Endpoint Security Framework, introduced in macOS 10.15 (Catalina), as a modern alternative to the OpenBSM subsystem for process monitoring. The Endpoint Security Framework provides a user-mode API that offers a simpler interface, comprehensive code-signing information, and proactive event response capabilities. This allows developers to create robust security tools for macOS without relying on kernel-level access, which Apple is actively deprecating. The framework requires the `com.apple.developer.endpoint-security.client` entitlement and the use of Xcode 11 or later with the macOS 10.15 SDK or newer. This framework enables process monitoring with details such as process ID, path, arguments, and code-signing information, simplifying the development of security tools like Ransomwhere?, TaskExplorer, and BlockBlock.

## Attack Chain

This attack chain represents how a malicious actor can potentially bypass security measures by exploiting the capabilities of process monitoring frameworks:

1.  **Initial Access:** A malicious program gains initial access to the macOS system through a vulnerability or social engineering.
2.  **Privilege Escalation:** The program attempts to escalate privileges to gain broader access to the system.
3.  **Process Creation:** The attacker creates a new process (e.g., `/tmp/evil.sh`) to execute malicious code on the system using `es_event_type_notify_exec`.
4.  **Code Injection:** The malicious process injects code into another running process to hide its activities.
5.  **Data Exfiltration:** The injected code collects sensitive data and attempts to exfiltrate it from the system.
6.  **Persistence:** The attacker establishes persistence by creating a launch agent or daemon.
7.  **Defense Evasion:** The attacker attempts to evade detection by modifying system files or disabling security tools.
8.  **Impact:** The attacker achieves their objectives, such as stealing sensitive data, disrupting system operations, or gaining control of the system.

## Impact

The successful exploitation of process monitoring frameworks and the subsequent bypass of security measures can lead to various detrimental outcomes. This includes unauthorized access to sensitive data, system compromise, and the disruption of critical services. The number of affected systems can range from individual machines to entire networks, depending on the scope of the attack.

## Recommendation

*   Enable Endpoint Security Framework logging to capture process execution events (`es_event_type_notify_exec`) for enhanced visibility.
*   Monitor for unexpected or unauthorized process creations, especially in sensitive directories like `/tmp` or `/var/tmp`, using a Sigma rule targeting `es_event_type_notify_exec`.
*   Implement code-signing verification to ensure that only trusted processes are allowed to execute, leveraging process code signing information.
*   Develop a detection rule to identify processes lacking proper code signatures or exhibiting suspicious signing characteristics.
*   Monitor the ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED error to detect unauthorized attempts to leverage the Endpoint Security framework.
