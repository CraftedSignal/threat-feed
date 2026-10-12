---
title: Credential Dumping via Symlink to Shadow Copy
slug: 2026-10-shadow-copy-symlink
description: Detection of attackers creating symbolic links to Volume Shadow Copies to bypass file system locks and access sensitive system files for credential theft.
date: "2026-10-12T17:38:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-dumping
  - windows
  - persistence
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The analytic detects the creation of a symlink to a shadow copy, which may indicate credential dumping attempts.
    confidence_band: high
references:
  - https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1003.003/T1003.003.yaml#L228
rules:
  - title: Detect Credential Dumping via Symlink to Shadow Copy
    description: Detects the use of mklink to create symbolic links to Volume Shadow Copies, a common technique for accessing SAM or NTDS.dit files.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy provided Sigma rule for mklink detection
      owner: Detection Engineering
      due: 48h
      evidence: Rule creation for T1003.003
  hunt_leads:
    - lead: Search for mklink executions involving shadow copy strings
      technique_id: T1003.003
      data_needed:
        - Process creation events with command line
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Known TTP for credential dumping
---

Attackers frequently target the Windows Volume Shadow Copy Service (VSS) to bypass file system permissions and locks that prevent direct access to sensitive system files. By creating a symbolic link to an existing shadow copy, an attacker can read restricted files such as the Security Account Manager (SAM) database or the Active Directory NTDS.dit file while the OS is running. This activity is a common precursor to credential dumping, allowing for offline password cracking or Golden Ticket generation. Identifying the execution of the `mklink` command in conjunction with shadow copy paths provides a high-fidelity signal for unauthorized access attempts that could lead to full domain or system compromise.

## Attack Chain

1. Attacker gains initial access and executes code with administrative privileges on a Windows host.
2. Attacker checks for existing volume shadow copies using `vssadmin list shadows` or WMI queries.
3. Attacker uses `mklink` to create a symbolic link (junction point) directed at a specific shadow copy volume (e.g., \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX).
4. Attacker accesses protected files (e.g., C:\Windows\System32\config\SAM) through the newly created junction point.
5. Attacker exfiltrates the hive files or performs local dumping using tools like Mimikatz or SecretsDump.
6. Attacker deletes the shadow copy or removes the symbolic link to clean up forensic artifacts.

## Impact

Successful exploitation allows an attacker to extract credentials from offline backups, which bypasses many traditional security controls that monitor live file access. This can result in complete account takeover, escalation of privileges, and long-term persistence within the environment, ultimately leading to significant data exfiltration or total domain compromise.

## Recommendation

* Deploy the provided Sigma rule to detect the use of `mklink` pointing to shadow copy paths on all Windows endpoints.
* Enable process-creation logging (e.g., Sysmon Event ID 1 or Security Event ID 4688) with full command-line arguments.
* Audit administrative account activity and restrict the ability of service accounts to execute `mklink` or interact with VSS.
