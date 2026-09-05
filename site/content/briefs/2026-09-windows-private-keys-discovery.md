---
title: Detection of Windows Private Key Discovery Activity
slug: 2026-09-windows-private-keys-discovery
description: Adversaries utilize native Windows utilities like cmd.exe and findstr.exe to search for sensitive private key files, a common post-exploitation technique used to facilitate credential theft, privilege escalation, and persistence.
date: "2026-09-05T00:02:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - discovery
  - post-exploitation
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The following analytic identifies processes that retrieve information related to private key files, often used by post-exploitation tools like winpeas.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1552/004/
  - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
  - https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/
rules:
  - title: Detect Windows Private Key Discovery via Command Line
    description: Detects the use of native Windows binaries to search for private key file extensions indicative of post-exploitation reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for recursive searches of key file extensions.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic logic implementation.
  hunt_leads:
    - lead: Search historical logs for process execution patterns involving common key extensions like .pfx and .pem.
      technique_id: T1552.004
      data_needed:
        - Process command line
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Observed in WinPEAS and similar post-exploitation tools.
---

Adversaries often perform discovery operations to locate sensitive files stored on an endpoint after initial access. This behavior frequently involves searching for various private key file formats, such as .key, .pfx, .pem, and .gpg, which can be leveraged to compromise encrypted communications, gain unauthorized access to remote services, or escalate privileges. Post-exploitation tools like WinPEAS automate this process, scanning directories for certificates and configuration files that contain sensitive credentials. Defenders can monitor for these activities by focusing on the execution of legitimate Windows binaries like cmd.exe, powershell.exe, and findstr.exe when they are invoked with command-line arguments containing specific file extension patterns indicative of private key material. This activity is a critical indicator of post-exploitation reconnaissance and warrants immediate investigation to prevent lateral movement or further environment compromise.

## Attack Chain

1. Attacker gains initial access to a Windows endpoint.
2. Attacker deploys a post-exploitation tool or uses native binaries (cmd.exe, powershell.exe).
3. Attacker executes discovery commands targeting the local filesystem to find key-related files.
4. Binary (e.g., findstr.exe or powershell.exe) performs recursive directory searches for specific extensions (e.g., .pem, .pfx, .key).
5. Attacker captures the output of these discovery commands to identify the location of insecurely stored keys.
6. Attacker reads or exfiltrates the identified private keys.
7. Attacker uses stolen credentials to maintain persistence, escalate privileges, or move laterally within the network.

## Impact

The discovery of private keys can lead to significant security breaches, including unauthorized access to authenticated services, decryption of sensitive traffic, and persistent unauthorized access to the environment. This activity is frequently observed in campaigns involving ransomware (e.g., Prestige Ransomware) and general-purpose post-exploitation frameworks where attackers seek to maximize the value of compromised hosts.

## Recommendation

1. Deploy the provided Sigma rule to detect suspicious command-line patterns associated with key discovery.
2. Enable Sysmon Event ID 1 or Windows Security Event ID 4688 to capture comprehensive process creation telemetry, including the full command line.
3. Map process logs to the CIM Endpoint data model to ensure consistency across security analytics and dashboards.
4. Investigate any findings from the detection rule by inspecting the command-line arguments to determine the intent of the execution.
