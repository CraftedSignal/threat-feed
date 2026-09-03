---
title: Credential Exfiltration via Volume Shadow Copy Service
slug: 2026-09-shadow-copy-exfiltration
description: Attackers leverage the Windows Volume Shadow Copy Service (VSS) to bypass file system locks and access sensitive credential stores like NTDS.dit or registry hives.
date: "2026-09-03T12:46:03Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: The technique uses shadow copies which can be used to inhibit recovery or facilitate credential access.
    confidence_band: high
references:
  - https://twitter.com/vxunderground/status/1423336151860002816
  - https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/
rules:
  - title: Detect Sensitive File Access via Volume Shadow Copy
    description: Detects the use of the Volume Shadow Copy device path to copy sensitive credential files such as NTDS.dit or registry hives.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting VSS-based exfiltration
  mitigation_plan:
    - priority: medium_term
      action: Restrict administrative rights to prevent unauthorized VSS creation
      owner: IT Operations
      evidence: Best practice for protecting credential stores
---

Threat actors frequently target credential stores on Windows systems to facilitate lateral movement and privilege escalation. By utilizing the Windows Volume Shadow Copy Service (VSS), attackers can create a point-in-time snapshot of the file system. This technique allows them to read files that are typically locked by the operating system, such as the Active Directory database (NTDS.dit), the SAM registry hive, or the SECURITY hive. Once the shadow copy is mounted, attackers use standard utilities like 'copy' or 'esentutl' to extract these files to staging directories. This approach is highly effective because it operates via legitimate system APIs, often avoiding traditional file-system integrity monitoring that triggers on direct file access of locked resources.

## Impact

Successful exploitation allows attackers to dump domain password hashes, local account credentials, and cached secrets. In enterprise environments, this often leads to the compromise of entire domains or significant escalation of privileges within a targeted network.

## Recommendation

Detection engineering teams should monitor process creation events for any execution involving the path syntax associated with Volume Shadow Copy.

* Deploy the provided Sigma rule to detect attempts to access sensitive files via shadow copy device paths.
* Enable Sysmon Event ID 1 (Process Creation) with command line logging enabled to capture the full path and arguments used by utilities like 'copy', 'esentutl', or 'vssadmin'.
* Restrict administrative privileges to prevent unauthorized creation or mounting of shadow copies.
* Implement file integrity monitoring (FIM) on the NTDS.dit and registry hive locations to identify unusual access patterns by non-system processes.
