---
title: Abuse of Mavinject for Process Injection
slug: 2026-09-mavinject-injection
description: Adversaries leverage the signed Windows binary mavinject.exe to perform unauthorized process injection by executing DLLs into running system processes.
date: "2026-09-03T13:46:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - living-off-the-land
  - process-injection
  - defense-evasion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
    evidence: Detects process injection using the signed Windows tool Mavinject via the INJECTRUNNING flag
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Adversaries leverage the signed Windows binary mavinject.exe to perform unauthorized process injection
    confidence_band: high
references:
  - https://posts.specterops.io/mavinject-exe-functionality-deconstructed-c29ab2cf5c0e
  - https://reaqta.com/2017/12/mavinject-microsoft-injector/
rules:
  - title: Detect Mavinject DLL Injection
    description: Detects process injection using the signed Windows tool Mavinject via the /INJECTRUNNING flag, excluding activity launched by the legitimate App-V client.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1055.001
      - T1218.013
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to detect mavinject.exe abuse
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief
  hunt_leads:
    - lead: Search process creation logs for mavinject.exe where ParentImage != AppVClient.exe
      technique_id: T1218.013
      data_needed:
        - Process creation telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of Mavinject functionality
---

Mavinject (mavinject.exe) is a signed Microsoft Windows utility originally designed for the Application Virtualization (App-V) environment. The tool provides a capability to inject a DLL into a running process using the /INJECTRUNNING flag. Because mavinject.exe is a trusted, signed binary, threat actors often use it as a Living-off-the-Land (LotL) technique to perform process injection while evading security controls that monitor for unsigned or suspicious executables. This technique allows an attacker to execute malicious code within the memory space of a legitimate, already-running process, potentially leading to privilege escalation or persistence. Defenders should monitor for execution of this binary where the parent process is not the legitimate App-V client.

## Impact

The abuse of this utility facilitates stealthy execution of malicious payloads, allowing attackers to hide their activity within the memory space of legitimate system or application processes. This can lead to unauthorized access to process data, privilege escalation, and evasion of endpoint detection mechanisms that rely on process reputation.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious invocations of mavinject.exe. Ensure that all command-line arguments are captured in process creation logs (Event ID 1). If mavinject.exe is not utilized by authorized App-V configurations in your environment, consider monitoring all instances of this binary regardless of the parent process.
