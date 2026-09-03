---
title: Credential Discovery via PowerShell Scripting
slug: 2026-09-powershell-credential-discovery
description: Adversaries use PowerShell to search local file systems and network shares for files containing embedded or insecurely stored credentials.
date: "2026-09-03T13:42:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - powershell
  - windows
  - discovery
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_extracting.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.001/T1552.001.md
rules:
  - title: Detect Credential Discovery via PowerShell Select-String
    description: Detects the use of PowerShell commands that recursively search file contents for sensitive patterns often used to discover stored credentials
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1552.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 48h
      evidence: Required for visibility into the TTP defined in the rule
  hunt_leads:
    - lead: Search for high-frequency use of Select-String by non-admin users
      technique_id: T1552.001
      data_needed:
        - Powershell Script Block logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This TTP is common in post-exploitation reconnaissance
  mitigation_plan:
    - priority: medium_term
      action: Remove plain-text credentials from configuration files and scripts
      owner: IT Operations
      addresses: T1552.001
      evidence: Reduces the attack surface for credential discovery
---

Adversaries often attempt to locate credentials stored within configuration files, source code, scripts, or binary files to facilitate lateral movement and privilege escalation. This technique involves using native PowerShell capabilities to recursively traverse directories and identify sensitive content using keyword pattern matching. By leveraging built-in cmdlets such as 'Select-String' combined with recursive listing commands like 'ls -R', attackers can efficiently scan large file systems for strings associated with passwords, API keys, or service account configurations. This approach is highly effective because it utilizes legitimate administrative tools, often blending in with normal system maintenance activity, and does not require the deployment of additional malicious binaries. Detection relies on monitoring PowerShell Script Block logs for combinations of specific commands indicative of recursive file content searching.

## Impact

Successful execution of this technique enables attackers to harvest credentials for further compromise of the environment. If credentials for administrative accounts or service accounts are identified, the impact can include unauthorized access to sensitive systems, increased persistence, and potential data exfiltration.

## Recommendation

- Enable and centralize PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints.
- Deploy the Sigma rule provided in this brief to identify suspicious recursive search patterns.
- Monitor for the execution of PowerShell commands that use 'Select-String' in conjunction with recursive listing flags against sensitive file paths.
- Implement access controls on configuration files and source code repositories to prevent unauthorized reading of credential stores.
