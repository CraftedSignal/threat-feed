---
title: WINDSHIFT APT Abuses Custom URL Schemes for macOS Infection
slug: 2024-01-windshift-mac-url-scheme
description: The WINDSHIFT APT group is infecting Macs by abusing custom URL schemes, where advertising support for a custom URL scheme in an application's Info.plist causes the application to be automatically launched when a URL with that scheme is opened, allowing attackers to remotely compromise systems with minimal user interaction and creating an initial access vector.
date: "2026-05-07T07:33:40Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - WINDSHIFT APT
tags:
  - macos
  - url-scheme
  - apt
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://objective-see.org/blog/blog_0x38.html
rules:
  - title: Detect Suspicious Custom URL Scheme Execution
    description: Detects suspicious process executions triggered by custom URL schemes, indicating potential exploitation of the technique used by WINDSHIFT APT.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - macos
  - title: Detect Info.plist Modification with Suspicious URL Schemes
    description: Detects modification of Info.plist files to include suspicious custom URL schemes, potentially indicating a malicious application installation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - macos
rules_count: 2
---

The WINDSHIFT APT group is utilizing a novel infection mechanism to compromise macOS systems, observed as early as 2018. This method involves exploiting custom URL schemes, allowing for remote exploitation with limited user interaction. By crafting a malicious application that registers a custom URL scheme, attackers can trigger its execution when a user interacts with a specially crafted link (e.g., via a web page or email). This initial access can then be leveraged for further exploitation, such as bypassing System Integrity Protection (SIP) or dumping the keychain. This technique has been successfully used against government targets in the Middle East.

## Attack Chain

1.  Attacker crafts a malicious application designed to register a custom URL scheme (e.g., `windshift://`). This is done by modifying the application's `Info.plist` file to include the `CFBundleURLTypes` key with the custom URL scheme.
2.  The victim downloads or saves the malicious application to their file system.
3.  macOS automatically registers the custom URL scheme when the application is saved to disk. This triggers an XPC message to the `launchservicesd` daemon.
4.  The `launchservicesd` daemon parses the application's `Info.plist` file, extracts the custom URL scheme, and registers it in its database.
5.  The attacker delivers a crafted link (e.g., via email or a web page) using the registered custom URL scheme (e.g., `<a href="windshift://payload">Click here</a>`).
6.  The victim clicks on the malicious link.
7.  The operating system consults its registered URL schemes and launches the malicious application.
8.  The malicious application executes arbitrary code, potentially downloading and installing further payloads, exfiltrating data, or establishing persistence.

## Impact

Successful exploitation allows the attacker to gain initial access to a macOS system. This can lead to the execution of arbitrary code, data exfiltration, and the installation of persistent backdoors. The WINDSHIFT APT group has successfully used this technique against government targets in the Middle East. If successful, this attack could result in the compromise of sensitive information, disruption of services, and reputational damage.

## Recommendation

*   Monitor process creation events for applications launched via custom URL schemes. Implement the `Detect Suspicious Custom URL Scheme Execution` Sigma rule to identify potential exploitation attempts.
*   Inspect application `Info.plist` files for suspicious or unexpected `CFBundleURLTypes` entries, especially during software installation or updates.
*   Educate users about the risks associated with clicking on untrusted links, even if they appear to be benign.
*   Enable process monitoring and auditing to capture details about process execution and file system changes.
*   Consider implementing application control policies to restrict the execution of unsigned or untrusted applications.
