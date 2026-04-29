---
title: Lucky Pasta Shellcode Loader for Windows
slug: 2026-03-lucky-pasta-shellcode-loader
description: A shellcode loader dubbed 'Lucky Pasta' employs JIT decryption, string obfuscation, dynamic library loading, fiber-based execution, and AES instruction patching to evade AV detection, retrieving shellcode via HTTP/HTTPS and executing it on Windows systems.
date: "2026-03-24T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - shellcode
  - windows
  - jit
  - defense-evasion
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
references:
  - https://www.reddit.com/r/cybersecurity/comments/1s1a04x/i_made_a_stealthy_jitd_shellcode_loader_that_i/
  - https://www.virustotal.com/gui/file/3e5a686e50683ecde0532b387d996153286747e7fbd2954b1c931150dc013562?nocache=1
  - https://github.com/Schich/Lucky-Pasta
iocs:
  - type: url
    value: https://www.virustotal.com/gui/file/3e5a686e50683ecde0532b387d996153286747e7fbd2954b1c931150dc013562?nocache=1
  - type: hash_sha256
    value: 3e5a686e50683ecde0532b387d996153286747e7fbd2954b1c931150dc013562
ioc_counts:
  hash_sha256: 1
  url: 1
rules:
  - title: Detect Shellcode Execution via Fibers
    description: Detects the creation of fibers, a technique used for stealthy shellcode execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1055
    data_sources:
      - process_creation
      - windows
  - title: Detect Process Retrieving Shellcode via HTTP/HTTPS
    description: Detects processes making outbound HTTP/HTTPS requests that are not common browsers, potentially indicating shellcode retrieval.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A newly developed shellcode loader, referred to as "Lucky Pasta", has been published online, showcasing advanced evasion techniques targeting Windows systems. The loader, written in C and utilizing the Windows API, is designed to bypass traditional antivirus (AV) solutions through a combination of runtime shellcode decryption using a Just-In-Time (JIT) approach, obfuscation of strings indicative of malicious intent, dynamic loading of libraries commonly flagged as suspicious, execution of shellcode within fibers for stealth, and runtime patching of Advanced Encryption Standard (AES) CPU instructions to thwart static analysis. The loader is capable of retrieving shellcode payloads via standard HTTP or encrypted HTTPS channels, indicating its potential use in various attack scenarios to deliver secondary payloads.

## Attack Chain

1. The shellcode loader is initially executed on a Windows system, likely through social engineering or exploitation of a software vulnerability.
2. The loader dynamically resolves API calls required for its operation, such as those related to memory allocation and network communication (e.g., `VirtualAlloc`, `LoadLibrary`, `GetProcAddress`).
3. The loader retrieves the encrypted shellcode from a remote server using HTTP or HTTPS protocols, potentially from a hardcoded URL.
4. The encrypted shellcode is decrypted in memory using the JIT decryption routine, converting it into executable code.
5. The loader creates a new fiber and transfers control to the decrypted shellcode within the fiber.
6. The shellcode performs its intended malicious actions, such as establishing a reverse shell or injecting into another process.
7. The loader cleans up any traces of its presence, such as zeroing out allocated memory regions.
8. The final objective is to gain unauthorized access to the compromised system, exfiltrate sensitive data, or deploy additional malware.

## Impact

Successful execution of the "Lucky Pasta" shellcode loader can lead to complete compromise of the target Windows system. Due to its evasion techniques, it can bypass standard AV detection. The use of HTTP/HTTPS for payload delivery allows it to operate from almost anywhere. Exploitation may lead to data theft, ransomware deployment, or use of the compromised system as a bot in a larger network.

## Recommendation

*   Monitor network traffic for processes making outbound HTTP/HTTPS requests to unusual or suspicious domains, as this is how the shellcode is retrieved (IOC table, network_connection log source).
*   Implement a process creation monitoring rule to detect processes that load suspicious libraries dynamically (e.g., `LoadLibrary` calls from unknown executables) to identify potential malicious loaders. (process_creation log source, Sigma rule)
*   Deploy the Sigma rules provided to detect shellcode execution via fibers and obfuscated strings. (process_creation log source, Sigma rule).
*   Inspect processes that perform memory allocation with execute permissions (`VirtualAlloc` with `PAGE_EXECUTE_READWRITE`), especially if followed by network activity.
