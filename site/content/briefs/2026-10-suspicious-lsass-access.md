---
title: Detection of Suspicious Access Masks for LSASS Process
slug: 2026-10-suspicious-lsass-access
description: This detection focuses on identifying unauthorized processes attempting to open handles to the Local Security Authority Subsystem Service (LSASS) using specific access masks often associated with credential dumping tools.
date: "2026-10-20T12:16:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - lsass
  - security-monitoring
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Detects process handle on LSASS process with certain access mask
    confidence_band: high
rules:
  - title: Potentially Suspicious AccessMask Requested From LSASS
    description: Detects process handles requested for lsass.exe with specific access masks associated with credential dumping techniques.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
      - security
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Audit Handle Manipulation and deploy Sigma rules
      owner: Detection Engineering
      due: 48h
      evidence: Source provides rules for detecting sensitive LSASS access
  hunt_leads:
    - lead: Search for processes (not in the whitelist) opening handles to lsass.exe
      technique_id: T1003.001
      data_needed:
        - Event ID 4656 and 4663
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Handle requests to LSASS with specific masks are indicative of memory dumping
---

The Local Security Authority Subsystem Service (LSASS) is a critical Windows process responsible for enforcing security policies and handling user authentication, including the storage of security tokens and cached credentials. Because LSASS maintains sensitive information in memory, it is a primary target for adversaries seeking to perform credential harvesting. Attackers use various tools to request process handles with specific access masks to read the memory space of lsass.exe. This detection monitors Windows Security event logs for handle requests (Event IDs 4656 and 4663) that specify access masks known to be used by common dumping utilities. Defenders should note that while this behavior is highly suspicious for unauthorized processes, many security products and administrative utilities also interface with LSASS, requiring rigorous tuning of the provided filters to minimize noise.

## Attack Chain

1. Attacker gains initial code execution on a compromised endpoint.
2. Attacker performs local enumeration to identify the location of lsass.exe.
3. Attacker uses a tool (e.g., Mimikatz, procdump) to request a handle to the LSASS process.
4. The tool specifies a high-privilege access mask (e.g., 0x1f0fff or similar) to allow memory access.
5. The Windows Security subsystem generates a handle request event (Event ID 4656).
6. The attacker reads the memory space of lsass.exe to extract credentials, hashes, or cleartext passwords.
7. The extracted credentials are exfiltrated or used for lateral movement within the network.

## Impact

Successful exploitation of LSASS via memory dumping results in the compromise of user credentials, which can lead to privilege escalation, lateral movement, and persistent access to the enterprise environment. If credentials for privileged accounts are obtained, the attacker can impersonate administrators and gain broad control over the domain.

## Recommendation

- Deploy the Sigma rules below to your SIEM to monitor for unauthorized handle requests to LSASS.
- Establish a baseline of legitimate software (AV, EDR, system utilities) that interacts with LSASS and add these to the exclusion filters.
- Enable Windows Security auditing for "Object Access" (specifically "Audit Handle Manipulation") to populate the necessary Event IDs.
- Investigate any alert that does not originate from a known, signed, and authorized security or management process.
