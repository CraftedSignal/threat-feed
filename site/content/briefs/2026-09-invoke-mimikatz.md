---
title: Detection of Mimikatz Credential Dumping via PowerShell
slug: 2026-09-invoke-mimikatz
description: This brief covers detection logic for identifying the use of the Mimikatz credential dumper within PowerShell scripts to extract sensitive Windows authentication material.
date: "2026-09-03T12:36:22Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml
  - https://www.elastic.co/guide/en/security/current/potential-invoke-mimikatz-powershell-script.html#potential-invoke-mimikatz-powershell-script
rules:
  - title: Detect Mimikatz PowerShell Script Blocks
    description: Detects the execution of known Mimikatz credential dumping commands within PowerShell scripts.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1003
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for credential dumping behavior.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific string signatures for Mimikatz detection.
  hunt_leads:
    - lead: Search historical Event ID 4104 logs for the identified command strings.
      technique_id: T1003
      data_needed:
        - PowerShell Operational logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Strings directly map to Mimikatz execution.
---

The Invoke-Mimikatz PowerShell script is a widely utilized post-exploitation tool designed to interact with the Windows Local Security Authority Subsystem Service (LSASS). By executing specialized memory-reading commands, the script enables attackers to extract plaintext credentials, Kerberos tickets, and digital certificates from memory. This technique is a cornerstone of credential access phases, allowing adversaries to escalate privileges or move laterally within a compromised network. Defenders should focus on Script Block Logging (Event ID 4104) to identify the execution of these specific function signatures and strings within the PowerShell runtime. While sometimes used by authorized penetration testers for security auditing, unauthorized execution of these commands is a strong indicator of an active credential theft attempt.

## Attack Chain

1. Attacker establishes an initial foothold on a Windows endpoint.
2. Attacker loads a PowerShell environment to execute post-exploitation commands.
3. Attacker imports or streams the Invoke-Mimikatz script into memory to avoid disk-based detection.
4. Attacker executes specific memory manipulation commands such as 'sekurlsa::logonpasswords' or 'DumpCreds'.
5. The script interfaces with LSASS to bypass security controls and scrape memory segments.
6. Attacker exfiltrates the recovered credentials to an external command-and-control server.
7. Attacker utilizes the stolen credentials to impersonate legitimate users or escalate privileges.

## Impact

Successful execution of Mimikatz allows an adversary to obtain plaintext passwords, NTLM hashes, and Kerberos tickets for users currently logged into the system. This level of access grants the attacker the ability to maintain persistence, impersonate high-privilege accounts (such as Domain Admins), and perform lateral movement, often leading to full domain compromise and significant data exfiltration.

## Recommendation

1. Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture script execution content.
2. Deploy the provided Sigma rule to your SIEM to monitor for known Mimikatz command strings in PowerShell script blocks.
3. Alert on any detected instances of 'sekurlsa::logonpasswords' or certificate dump functions.
4. Conduct an immediate investigation if these commands are identified on high-value systems like domain controllers or workstations belonging to administrative personnel.
