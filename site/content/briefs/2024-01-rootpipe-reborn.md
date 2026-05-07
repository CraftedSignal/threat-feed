---
title: macOS Privilege Escalation via Feedback Assistant Race Condition (CVE-2019-8565)
slug: 2024-01-rootpipe-reborn
description: A race condition vulnerability (CVE-2019-8565) exists in macOS where a privileged XPC service, com.apple.appleseed.fbahelperd, improperly validates XPC messages based on process ID, allowing an unprivileged process to escalate privileges to root.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - macos
  - xpc
  - race-condition
vendors:
  - Apple
products:
  - macOS
  - iOS
affected_os:
  - macOS 10.14.3
  - iOS 12.2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2019-8565
    cvss: 7
    epss: 0.2874
references:
  - https://objective-see.org/blog/blog_0x41.html
rules:
  - title: Detect Suspicious File Copy via FBAPrivilegedDaemon
    description: Detects suspicious file copy operations performed by FBAPrivilegedDaemon, indicating potential exploitation of CVE-2019-8565. Specifically, this rule looks for the copyLogFiles method being called.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1027
      - T1068
    data_sources:
      - process_creation
      - macos
  - title: Detect Execution of netdiagnose from get-mobility-info
    description: Detects execution of /usr/local/bin/netdiagnose by the get-mobility-info script, indicating potential exploitation of CVE-2019-8565 via the runMobilityReportWithDestination method.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

The vulnerability, CVE-2019-8565, resides in macOS versions prior to 10.14.4 and iOS versions prior to 12.2. It involves a race condition in the privileged XPC service `com.apple.appleseed.fbahelperd`, used by the Feedback Assistant application. This service incorrectly validates incoming XPC messages based on process IDs (PIDs) instead of more secure methods like audit tokens. An unprivileged or sandboxed process can exploit this by rapidly spawning processes to reuse PIDs, tricking the privileged service into accepting malicious requests. This allows attackers to bypass security checks and execute privileged operations, ultimately leading to privilege escalation to root. The original research was published in April 2019, highlighting the risks associated with PID-based security checks in inter-process communication.

## Attack Chain

1. An unprivileged process sends multiple XPC messages to `com.apple.appleseed.fbahelperd` to fill the message queue.
2. The unprivileged process spawns a new process (using `posix_spawn` or `NSTask`) to reuse the PID while keeping the new process suspended.
3. The `FBAPrivilegedDaemon` validates the XPC message based on the reused PID, incorrectly associating it with the trusted Feedback Assistant application.
4. The attacker exploits the `copyLogFiles:` method to copy arbitrary files by bypassing path constraints using path traversal (e.g., "../../../").
5. Files are copied to attacker-controlled locations, bypassing intended permission restrictions.
6. Alternatively, the attacker leverages `runMobilityReportWithDestination:` to trigger execution of `/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Resources/get-mobility-info`.
7. The `get-mobility-info` script checks for `/usr/local/bin/netdiagnose` and executes it with root privileges if found.
8. The attacker gains root privileges by executing a custom `netdiagnose` binary in `/usr/local/bin`.

## Impact

Successful exploitation of CVE-2019-8565 allows a local attacker to gain root privileges on vulnerable macOS systems. This can lead to complete system compromise, including unauthorized access to sensitive data, installation of malware, and modification of system configurations. The vulnerability impacts systems running macOS 10.14.3 and earlier, as well as iOS 12.2 and earlier. In CTF scenarios, it was used to directly read flag files. If an attacker can plant a binary in a location like /usr/local/bin, they can achieve instant root access.

## Recommendation

*   Upgrade to macOS 10.14.4 or later to patch CVE-2019-8565.
*   Deploy the Sigma rule "Detect Suspicious File Copy via FBAPrivilegedDaemon" to detect exploitation attempts targeting the `copyLogFiles:` method.
*   Deploy the Sigma rule "Detect Execution of netdiagnose from get-mobility-info" to detect attempts to exploit the `runMobilityReportWithDestination:` method.
*   Monitor process creations for suspicious binaries executing from `/usr/local/bin` as described in the Attack Chain.
