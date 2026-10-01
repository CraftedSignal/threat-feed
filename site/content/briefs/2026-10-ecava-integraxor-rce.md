---
title: Unauthenticated Remote Code Execution in Ecava IntegraXor IGX
slug: 2026-10-ecava-integraxor-rce
description: Ecava IntegraXor IGX 16.0.701.10 is vulnerable to unauthenticated remote code execution via an insecure file upload endpoint that enables arbitrary command execution during service startup.
date: "2026-10-01T15:12:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - scada
  - rce
  - ot
vendors:
  - Ecava
products:
  - IntegraXor IGX (16.0.701.10)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The DX Web HMI server (dxweb.exe) has NO authentication on any endpoint. Its /FileUpload endpoint takes an attacker-controlled copyTo destination directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: Builds the command line 'cmd.exe /C <meta.name>' and runs it via Process.Start.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The payload executes at the next dxmanager start/restart (cmd.exe /C <meta.name>).
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52688
rules:
  - title: Detect Suspicious Command Execution from dxmanager
    description: Detects cmd.exe being spawned by dxmanager.exe, which is indicative of exploitation of the IGX RCE vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - OT Security
    - Detection Engineering
  immediate_actions:
    - action: Restrict access to port 8081 for IntegraXor IGX servers.
      owner: OT Security
      due: 24h
      evidence: Unauthenticated web endpoint exposure identified as the primary vector.
    - action: Deploy Sigma detection rule for dxmanager spawning cmd.exe.
      owner: Detection Engineering
      due: 24h
      evidence: Exploitation chain requires spawning cmd.exe from dxmanager process.
  mitigation_plan:
    - priority: immediate
      action: Disable the /FileUpload endpoint or restrict service access at the network boundary.
      owner: IT Operations
      addresses: RCE vulnerability
      evidence: Vulnerability allows unauthenticated file writing to arbitrary locations.
---

Ecava IntegraXor IGX version 16.0.701.10 contains a critical remote code execution vulnerability originating from an unauthenticated file upload endpoint. The DX Web HMI server (dxweb.exe) exposes a /FileUpload endpoint that lacks authentication and sanitization, allowing remote attackers to write arbitrary files to the underlying Windows host. By uploading a batch script to a temporary directory and a crafted configuration JSON file into the dxmanager configuration directory, an attacker can manipulate the dxmanager.exe orchestrator. Upon service startup or restart, dxmanager.exe enumerates the configuration directory and executes any defined files via cmd.exe /C, resulting in command execution with the privileges of the BUILTIN\Administrators account. This vulnerability specifically impacts OT and CII manufacturing environments where IntegraXor is deployed as a SCADA/HMI solution.

## Attack Chain

1. Attacker sends an unauthenticated POST request to the /FileUpload endpoint on the target IGX web server (port 8081).
2. Attacker provides the 'copyTo' parameter set to 'C:\Windows\Temp\' and uploads a malicious batch file (igx_payload.bat) containing attacker-specified commands.
3. Attacker sends a second unauthenticated POST request to the /FileUpload endpoint.
4. Attacker provides a 'copyTo' parameter pointing to the dxmanager configuration directory and uploads a configuration JSON file (igx_poc.json).
5. The JSON file is crafted with a 'meta.name' field containing the absolute path to the previously uploaded batch file (e.g., 'C:\Windows\Temp\igx_payload.bat').
6. The dxmanager.exe process is triggered to restart via system reboot, service update, crash recovery, or an unauthenticated MQTT Command.Restart.
7. During initialization, dxmanager.exe enumerates the configuration directory, reads the malicious JSON file, and invokes 'cmd.exe /C C:\Windows\Temp\igx_payload.bat'.
8. Arbitrary commands execute with BUILTIN\Administrators privileges, achieving full system compromise.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary code with administrative privileges on the SCADA/HMI server. This poses a severe risk to operational technology environments, potentially enabling full control over industrial processes, manipulation of HMI data, and lateral movement within the industrial network.

## Recommendation

1. Restrict network access to the IntegraXor DX Web HMI server (default port 8081) to authorized management workstations only, effectively isolating it from the public internet.
2. Implement strict firewall controls to block access to the /FileUpload endpoint from untrusted networks.
3. Deploy the Sigma rules below to monitor for suspicious process execution patterns originating from the dxmanager service.
4. Hunt for anomalous file creation events in the dxmanager configuration directory and C:\Windows\Temp\ involving .bat or .json files.
5. Coordinate with the vendor, Ecava, to obtain security patches and disable non-essential features, specifically the /FileUpload functionality, until a verified fix is applied.
