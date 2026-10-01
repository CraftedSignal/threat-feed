---
title: Claude Desktop Cowork VM Boot Image Tampering
slug: 2026-10-claude-cowork-tamper
description: Adversaries with user-level access can perform defense evasion by overwriting Claude Desktop Cowork VM boot images to execute malicious code within a virtualized guest.
date: "2026-10-01T20:06:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Anthropic
products:
  - Claude Desktop
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: By replacing these files with malicious versions, an attacker can execute arbitrary code within a virtualized guest environment.
    confidence_band: high
rules:
  - title: Claude Cowork VM Boot Image Tamper
    description: Detects unauthorized modification of Claude Desktop Cowork VM boot images by non-legitimate processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.006
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the provided Sigma rule to monitor write access to Claude vm_bundles
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific file paths for monitoring
  hunt_leads:
    - lead: Unauthorized processes writing to Claude vm_bundles directory
      technique_id: T1564.006
      data_needed:
        - File modification logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation identifies this as a post-compromise defense evasion signal
  mitigation_plan:
    - priority: short_term
      action: Monitor environment for abnormal process activity within user-accessible application data directories
      owner: SOC
      addresses: Defense Evasion
      evidence: Source notes that tampering is a signal of post-compromise activity
---

Claude Desktop features a functionality called 'Cowork' that utilizes a local virtual machine to execute tasks. This VM is booted from a set of image files (kernel, initrd, and root filesystem) stored within the user's application data directory. Because these files are writable by the standard user context and lack integrity verification prior to the boot process, an adversary who has gained user-level access to the host machine can overwrite these images with attacker-controlled versions. 

When the user subsequently launches a Cowork session, the virtual machine boots the modified environment. This allows attackers to run arbitrary code inside a sanctioned virtualization container. This technique is particularly dangerous for defense evasion because host-based endpoint detection and response (EDR) solutions often do not inspect activity occurring inside these guest virtual machines by default. This does not grant the attacker elevated privileges on the host itself, but effectively hides malicious activity from standard monitoring visibility.

## Impact

Successful exploitation allows attackers to execute arbitrary code within a virtualized, isolated environment, effectively bypassing host-level security monitoring. While this does not grant the attacker direct host administrative privileges, it provides a persistent mechanism to hide malicious guest-side activity from EDR solutions. This threat affects all users of Claude Desktop on Windows and macOS who utilize the Cowork feature. 

## Recommendation

Detection engineering teams should deploy rules to monitor for unauthorized writes to the Claude vm_bundles directory.

- Enable file integrity monitoring (FIM) or process-based file modification logging on the specific paths listed in the Sigma rule below.
- Investigate any process other than the legitimate `claude.exe` or `Claude` Helper that attempts to write to the `vm_bundles` directory.
- If tampering is detected, isolate the host and restore the `vm_bundles` directory from a known-good backup or by letting the Claude application re-download the verified images.
- Hunt for the initial access vector that allowed the unauthorized writer process to execute on the host.
