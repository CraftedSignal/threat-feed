---
title: Local Privilege Escalation in Lima via Guest Agent Socket
slug: 2026-08-lima-guest-agent-privesc
description: An arbitrary user within a QEMU-based Lima VM can exploit improper access controls on the guest agent Unix socket (/run/lima-guestagent.sock) to execute arbitrary commands with root privileges within the guest VM.
date: "2026-08-14T20:06:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - virtualization
  - cve-2026-53657
vendors:
  - Lima
products:
  - Lima (<= 2.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An arbitrary user in the VM could access /run/lima-guestagent.sock... which could result in running an arbitrary command with the root privileges in the VM.
    confidence_band: high
cves:
  - id: CVE-2026-53657
    cvss: 8.2
    epss: 0.00129
references:
  - https://github.com/advisories/GHSA-2j9v-p4xj-cjw2
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Lima to v2.1.3 across all development environments.
      owner: IT Operations
      due: 72h
      evidence: Patched in Lima v2.1.3
  mitigation_plan:
    - priority: immediate
      action: Switch to 'vz' driver for new VMs or disable guest agent.
      owner: IT Operations
      addresses: CVE-2026-53657
      evidence: Workarounds provided in advisory.
---

Lima, a project providing Linux virtual machines on macOS, contains a vulnerability (CVE-2026-53657) affecting instances using the QEMU driver. An arbitrary user within the guest VM can access the guest agent Unix socket located at /run/lima-guestagent.sock. Because this socket provides tunneling services for arbitrary addresses, including those used by privileged system daemons like D-Bus, an unprivileged user can craft requests to execute arbitrary commands with root privileges within the guest instance. This issue is specific to the QEMU driver; the 'vz' driver is unaffected as it utilizes vsocks. The vulnerability is patched in Lima version 2.1.3.

## Impact

The vulnerability allows for local privilege escalation (LPE) within the context of a Lima virtual machine. Successful exploitation grants an unprivileged guest user root-level command execution. The scope is limited to the VM instance itself and does not directly result in root access on the macOS host.

## Recommendation

- Upgrade the Lima installation to version 2.1.3 or higher to address CVE-2026-53657.
- If upgrading is not immediately feasible, switch to the 'vz' driver for VM instances using 'limactl create --vm-type=vz' or disable the guest agent using the '--plain' flag during VM creation.
- Audit existing VM configurations to identify instances currently using the QEMU driver.
