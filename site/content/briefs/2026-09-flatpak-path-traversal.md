---
title: Path Traversal Vulnerability in Flatpak App Deployment
slug: 2026-09-flatpak-path-traversal
description: A path traversal vulnerability in Flatpak allows malicious applications to overwrite or replace critical host system files with symlinks during deployment, with root-level impacts for system-wide installations.
date: "2026-09-29T06:25:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:flatpak:flatpak:*:*:*:*:*:*:*:*
vendors:
  - Flatpak
products:
  - Flatpak (all versions prior to fix)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: In system-wide installations, the write is performed as root.
    confidence_band: high
cves:
  - id: CVE-2026-97024
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97024
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Flatpak installations to the latest patched version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-97024 advisory
  hunt_leads:
    - lead: Detect file modifications to sensitive host /etc files by flatpak helper processes
      technique_id: T1068
      data_needed:
        - Auditd or Sysmon for Linux process/file activity
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows replacement/emptying of /etc/passwd, group, machine-id, resolv.conf
  mitigation_plan:
    - priority: immediate
      action: Apply distribution-provided patches for Flatpak
      owner: IT Operations
      addresses: CVE-2026-97024
      evidence: NVD advisory
---

CVE-2026-97024 is a path traversal vulnerability residing within the Flatpak packaging subsystem. During the deployment phase of application installation or updates, Flatpak fails to properly sanitize the handling of the files/etc directory. A malicious application, crafted to exploit this flaw, can navigate outside of its intended sandbox constraints and target sensitive files on the host filesystem. Observed targets include critical system configuration files such as /etc/passwd, /etc/group, /etc/machine-id, and /etc/resolv.conf.

When these operations occur during a system-wide Flatpak installation, the malicious actions are performed with root privileges, effectively allowing an attacker to clear the contents of sensitive files or replace them with malicious symlinks. This behavior leads to significant system instability, potential privilege escalation, or modification of security-critical system state. Defenders should prioritize auditing Flatpak installation sources and monitoring for anomalous file modifications originating from the flatpak system daemon.

## Impact

Successful exploitation allows for the compromise of system-wide integrity. By manipulating files like /etc/passwd or /etc/resolv.conf, an attacker can disrupt system authentication or redirect network traffic. As these operations occur with root privileges, this represents a severe vulnerability for Linux systems utilizing system-wide Flatpak installations, particularly in multi-user or shared environments.

## Recommendation

Prioritize patching all Flatpak installations to the latest version provided by your distribution as soon as the security update is available. Monitor host filesystem activity for unauthorized changes to critical configuration files in the /etc directory, specifically focusing on modifications where the initiating process is the flatpak-system-helper or related daemon.
