---
title: Suspicious Child Process Execution via Azure VM CustomScript Extension
slug: 2026-07-azure-customscript-suspicious-child
description: Attackers with access to an Azure subscription or VM management plane can leverage the Azure VM CustomScript extension to execute arbitrary code with SYSTEM privileges on Windows virtual machines, leading to various malicious activities such as reconnaissance, malware deployment, and persistence.
date: "2026-07-17T12:59:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - execution
  - cloud-to-host
  - azure
  - lolbin
vendors:
  - Microsoft
products:
  - Azure Virtual Machines CustomScript Extension
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
    evidence: The Azure CustomScript extension executes a script as SYSTEM via the guest agent. The extension's resource name is attacker-controlled and not present on the host, so this rule anchors on the handler binary path (`Microsoft.Compute.CustomScriptExtension\...\CustomScriptHandler.exe`), which is rename-proof, and alerts when a LOLBin or suspicious PowerShell runs anywhere in its process tree.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: CustomScript legitimately launches PowerShell and cmd, so the rule fires only when the descendant is an execution-proxy, download, or discovery LOLBin, or PowerShell exhibiting suspicious tradecraft.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: CustomScript legitimately launches PowerShell and cmd, so the rule fires only when the descendant is an execution-proxy, download, or discovery LOLBin, or PowerShell exhibiting suspicious tradecraft.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The rule fires only when the descendant is an execution-proxy, download, or discovery LOLBin, or PowerShell exhibiting suspicious tradecraft.
    confidence_band: high
references:
  - https://blog.pwnedlabs.io/diving-deep-into-azure-vm-attack-vectors
  - https://www.sysdig.com/blog/the-expendable-extension-name-azure-vmaccess-naming-chaos-password-resets-and-a-detection-gap
  - https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
rules:
  - title: Suspicious Child Process via Azure VM CustomScript Extension
    description: Detects suspicious processes (LOLBins, script hosts, or PowerShell with suspicious tradecraft) launched as direct children of the Azure VM CustomScript extension handler (CustomScriptHandler.exe). This rule aims to identify arbitrary code execution following the deployment of a malicious CustomScript extension.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1059.001
      - T1059.003
      - T1218
      - T1651
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Attackers who gain initial access to an Azure subscription or virtual machine management plane can exploit the Azure VM CustomScript extension to achieve highly privileged code execution on Windows hosts. This technique involves deploying an attacker-controlled script, which is then executed by the `CustomScriptHandler.exe` binary via the Azure Guest Agent, typically running with SYSTEM privileges. This capability represents a common and critical cloud-to-host pivot, allowing adversaries to establish a strong foothold within target environments. The detection mechanism focuses on identifying suspicious descendant processes launched by `CustomScriptHandler.exe`, specifically targeting known Living-Off-The-Land (LOLBins) used for execution, download, or discovery, as well as PowerShell commands exhibiting suspicious tradecraft (e.g., encoded commands, download cradles). This approach allows for robust detection even when attackers attempt to obfuscate their activities by manipulating the extension's resource name, which is not reflected in on-host telemetry.

## Attack Chain

1. Attacker gains initial access to the target Azure subscription or VM management plane, potentially via compromised credentials, misconfigurations, or exploitation of other vulnerabilities.
2. The attacker creates or updates an Azure VM CustomScript Extension on a target Windows virtual machine, specifying a malicious script or command to be executed.
3. The Azure Guest Agent on the target VM receives the extension deployment command and downloads the attacker-supplied script or payload.
4. The `CustomScriptHandler.exe` process is launched by the Azure Guest Agent, executing the attacker's script with SYSTEM privileges.
5. `CustomScriptHandler.exe` spawns a suspicious child process, which could be an execution-proxy (e.g., `mshta.exe`, `regsvr32.exe`), a download tool (`certutil.exe`, `bitsadmin.exe`), a script host (`wscript.exe`, `cscript.exe`), a discovery utility (`whoami.exe`, `net.exe`, `wmic.exe`), or a PowerShell instance running encoded commands or download cradles.
6. The malicious child process executes its payload, which can include further reconnaissance, downloading and installing additional malware, establishing persistence mechanisms, or directly impacting the system (e.g., data exfiltration, ransomware deployment).

## Impact

Successful exploitation of the Azure VM CustomScript extension grants attackers arbitrary code execution with SYSTEM privileges on the affected Windows virtual machine. This level of access enables comprehensive control over the compromised system, allowing for complete data compromise, installation of persistence mechanisms, deployment of ransomware, exfiltration of sensitive information, or lateral movement within the network. The impact can extend beyond the single VM, potentially affecting an entire Azure environment if the compromised VM hosts critical services or provides a pivot point to other cloud resources. Organizations may face significant operational disruption, data breaches, and financial losses due to remediation efforts and regulatory fines.

## Recommendation

* Deploy the Sigma rule "Suspicious Child Process via Azure VM CustomScript Extension" to your SIEM and configure `process_creation` logging for Windows endpoints to detect malicious execution.
* Review all `process_creation` logs for `CustomScriptHandler.exe` spawning suspicious child processes, specifically those matching the LOLBin and PowerShell patterns outlined in the Sigma rule.
* Correlate alerts with `MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE` events in `logs-azure.activitylogs-*` around the same time to identify the principal and source behind the CustomScript extension deployment.
* For recurring, known automation activities identified as false positives, create specific exclusions for `process.command_line` or `process.args` rather than broad exclusions on process names or parent images.
* If unauthorized activity is confirmed, remove the suspicious CustomScript extension, isolate the affected VM, rotate all credentials potentially compromised from the VM, and review RBAC permissions on the associated Azure subscription or resource group.
