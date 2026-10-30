---
brief_id: brief-2026-10-30-mikrotik-routeros-mtget-overflow
event_id: brief-2026-10-30-mikrotik-routeros-mtget-overflow
revision: 1
activity_at: "2026-10-30T23:04:32Z"
title: 'MikroTik RouterOS: Persistent Privilege Escalation via mtget Stack Overflow (CVE-2026-89020)'
slug: 2026-10-mikrotik-routeros-mtget-overflow
description: An authenticated, low-privileged user can trigger a stack-based buffer overflow in the RouterOS mtget binary via a crafted TFTP fetch request to gain persistent administrative privileges.
date: "2026-10-30T23:04:32Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - network-device
  - routeros
vendors:
  - MikroTik
products:
  - RouterOS (< 6.49.21)
  - RouterOS (7.23.0 - 7.23.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A stack overflow in the TFTP RRQ builder of the mtget binary, reachable via /tool fetch with an over-long tftp:// URL path, is used to overwrite saved registers and rewrite the stored policy.
    confidence_band: high
cves:
  - id: CVE-2026-89020
    cvss: 4.3
    epss: 0.00488
    kev_status: "false"
references:
  - https://mikrotik.com/supportsec/cve-2026-89020/
  - https://www.vulncheck.com/advisories/mikrotik-routeros-stack-buffer-overflow-via-tftp-url-path
  - https://sploitus.com/exploit?id=9083E69A-424A-5498-8391-D9DACEABD2FD&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch all vulnerable RouterOS devices to fixed versions 6.49.21 or 7.23.4.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability remediation requires firmware update as per vendor advisory.
  hunt_leads:
    - lead: Monitor for suspicious use of the /tool fetch command with overly long URL paths.
      technique_id: T1068
      data_needed:
        - RouterOS terminal audit logs (if enabled)
        - Remote management command history
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The PoC utilizes /tool fetch with a 4094 byte path to trigger the overflow.
  mitigation_plan:
    - priority: immediate
      action: Upgrade RouterOS firmware to version 6.49.21 or 7.23.4.
      owner: IT Operations
      addresses: CVE-2026-89020
      evidence: Vendor advisory confirms these versions contain the bounded-copy fix.
---

A stack-based buffer overflow vulnerability (CVE-2026-89020) exists in the 'mtget' binary of MikroTik RouterOS within the TFTP request (RRQ) builder. Authenticated, low-privileged users can exploit this by issuing a maliciously crafted '/tool fetch' command with an excessively long tftp:// URL path. This allows for the overwriting of registers and the modification of the system's group policy configuration file ('/rw/store/group.dat'). Consequently, accounts with read-only access can be promoted to full-privileged status, with the configuration changes persisting across device reboots.

## Attack Chain
1. Authenticated user identifies an unpatched RouterOS instance.
2. User initiates a loopback TFTP fetch command using '/tool fetch'.
3. User provides a crafted, over-long (4094 B) tftp:// URL path as the source-path parameter.
4. The mtget binary performs an unbounded memory copy, triggering a stack overflow.
5. The overflow overwrites saved registers, allowing the attacker to redirect execution.
6. The process modifies '/rw/store/group.dat', altering policy definitions to grant full privileges to the 'read' group.
7. The device reboot process loads the corrupted group file, establishing persistent administrative access for the attacker.

## Impact
Successful exploitation results in full administrative control over the affected network appliance. The change to the group policy file is persistent and survives device reboots, potentially leading to long-term unauthorized access and control of the network infrastructure.

## Recommendation
- Upgrade RouterOS to version 6.49.21 or later, or 7.23.4 or later, to receive the fix for CVE-2026-89020.
- Audit existing RouterOS instances for unauthorized modifications to group policies using 'group print detail'.
- Restrict access to the '/tool fetch' command and TFTP functionality to authorized administrative users only.
- Implement network-level segmentation to prevent low-privileged users from reaching sensitive device management interfaces.
