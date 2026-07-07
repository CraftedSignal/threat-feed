---
title: Suspicious Java Execution from User-Writable Paths with DNS Lookup
slug: 2026-07-java-dropped-executed-dns
description: This brief describes the detection of suspicious `javaw.exe` execution on Windows systems by adversaries leveraging recently dropped or modified Java payloads from user-writable directories (e.g., `Users`, `ProgramData`, `Windows\Temp`) to establish command and control via immediate DNS lookups, thereby evading application control mechanisms.
date: "2026-07-03T16:34:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - java
  - execution
  - command-and-control
  - windows
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Identifies a recently dropped or modified javaw.exe process started from a user-writable path to run a JAR or Java classpath application
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Adversaries may drop Java payloads into user directories and execute them immediately
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: followed by a DNS lookup. Adversaries may ... establish command and control
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_java_dropped_jar_immediate_dns_lookup.toml
rules:
  - title: Suspicious Java Execution from User-Writable Paths
    description: Detects javaw.exe executing JAR or Java classpath applications from user-writable paths like Users, ProgramData, or Windows\Temp, which is a common technique for adversaries to execute dropped Java payloads.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Adversaries are known to deploy malicious Java applications (JARs or classpath-based applications) to Windows systems, often by dropping them into user-writable locations such as user profiles, `ProgramData`, or the `Windows\Temp` directory. These applications are then executed using `javaw.exe`, typically with arguments like `-jar` or `-cp` (classpath). The threat identified involves such an execution immediately followed by an outbound DNS lookup, indicating an attempt to establish command and control (C2) infrastructure. This technique allows attackers to bypass application control mechanisms that primarily focus on native Windows executables, as `javaw.exe` itself is a legitimate binary. The timing is critical, focusing on `javaw.exe` processes that were recently created or modified, suggesting a staged payload.

## Attack Chain

1.  **Initial Access:** (Unspecified by the detection rule, but assumed) An attacker gains initial access to a Windows system through various means (e.g., phishing, exploit of a vulnerable service, compromised credentials).
2.  **Payload Staging:** A malicious Java payload (e.g., a `.jar` file or a collection of Java classes) is dropped onto the compromised system into a user-writable directory like `C:\Users\<username>\AppData\Local\Temp`, `C:\ProgramData\`, or `C:\Windows\Temp\`.
3.  **Execution from Suspicious Path:** The attacker executes the `javaw.exe` process from one of these user-writable locations.
4.  **Java Application Launch:** The `javaw.exe` process is launched with specific arguments, such as `-jar malicious.jar` or `-cp <classpath> MainClass`, to run the staged malicious Java application.
5.  **Command and Control (C2) Initiation:** The malicious Java application immediately attempts to perform a DNS lookup, aiming to resolve the IP address of its command and control server.
6.  **Establishing C2 Channel:** Upon successful DNS resolution, the malicious application attempts to establish a communication channel with the C2 server to receive further commands or exfiltrate data.
7.  **Impact (Further Compromise):** The established C2 channel enables the attacker to perform further actions, including data exfiltration, deploying additional malware, or maintaining persistence.

## Impact

Successful exploitation allows attackers to establish a covert command and control channel, giving them persistent access to the compromised system. This can lead to unauthorized data exfiltration, further malware deployment (e.g., ransomware, infostealers), lateral movement within the network, and full system compromise. The ability to execute malicious code via a legitimate Java runtime from user-writable locations makes this technique difficult to detect for organizations relying solely on traditional application whitelisting and can result in significant financial, reputational, and operational damage.

## Recommendation

*   Deploy the provided Sigma rule for "Suspicious Java Execution from User-Writable Paths" to your SIEM/EDR and tune it for your environment.
*   Review `process.executable`, `process.command_line`, and `process.args` for any alerts generated by the Sigma rule to identify the specific JAR or classpath targeted and its legitimacy.
*   Enable Sysmon process-creation and DNS query logging to correlate `javaw.exe` processes with subsequent DNS lookups, mirroring the correlation logic described in the original detection rule.
*   Inspect parent processes of `javaw.exe` detections to identify the initial delivery mechanism (e.g., archive extraction, script execution) that dropped the Java payload.
*   Investigate `dns.question.name` and `dns.resolved_ip` for suspicious DNS queries originating from `javaw.exe` processes.
