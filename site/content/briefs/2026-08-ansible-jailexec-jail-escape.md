---
title: Ansible jailexec Plugin Jail Escape via Symlink Following
slug: 2026-08-ansible-jailexec-jail-escape
description: The ansible_jailexec connection plugin performs file operations with host-side root privileges while following symlinks, allowing an attacker to escape a FreeBSD jail and gain root access on the host.
date: "2026-08-13T04:48:33Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Ansible
products:
  - ansible_jailexec
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A party controlling content inside a managed jail can therefore cause an arbitrary root-owned write on the host, outside the jail a full jail escape.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cxgv-hp74-jj7r
  - https://github.com/chofstede/ansible_jailexec/blob/main/docs/security/advisory-2.0.0-jail-escape.md
  - https://github.com/chofstede/ansible_jailexec/pull/6
---

The ansible_jailexec connection plugin (versions prior to 2.0.0) is susceptible to a critical jail escape vulnerability identified as CVE-2026-55074. The plugin's 'put_file' operation, intended for transferring files into a managed jail, incorrectly resolves destination paths by concatenating the jail root with the target path and executing 'mkdir' and 'mv' commands on the host filesystem with root privileges. Because these host-side commands follow symbolic links, an attacker who controls content within the jail can place a symbolic link at or above a target path. When an Ansible task subsequently executes a file transfer, the host-side process follows this symlink, leading to an arbitrary write outside the jail's chroot. An attacker can leverage this primitive to overwrite sensitive host files, such as 'authorized_keys' or 'cron' jobs, effectively escaping the jail and gaining root-level control over the host.

## Attack Chain

1. The attacker gains initial access or control over a subdirectory within a FreeBSD jail managed by the vulnerable 'ansible_jailexec' plugin.
2. The attacker identifies or predicts a forthcoming Ansible task (e.g., 'copy', 'template', or 'fetch') targeting a specific location within the jail.
3. The attacker creates a malicious symbolic link at the target location, pointing to a sensitive file on the host filesystem (e.g., '/etc/passwd' or '/root/.ssh/authorized_keys').
4. An operator initiates the legitimate Ansible task, which invokes the 'put_file' method of the 'ansible_jailexec' plugin.
5. The Ansible host-side process runs 'mkdir' and 'mv' commands as root to finalize the file transfer.
6. The host-side commands resolve the attacker-controlled symlink and proceed to write or move content to the host's protected target location.
7. The attacker succeeds in overwriting critical host system files, completing the jail escape and achieving host-level code execution.

## Impact

Successful exploitation results in a full jail escape and host compromise. By overwriting configuration files or adding SSH keys, an attacker can obtain persistent root-level access to the underlying FreeBSD host. This vulnerability affects all environments utilizing 'ansible_jailexec' versions 1.3.0 and earlier to manage FreeBSD jails, with significant security implications for multi-tenant or delegated administration setups where jail isolation is a core security boundary.

## Recommendation

Prioritized actions for detection and remediation:
- Upgrade 'ansible-jailexec' to version 2.0.0 or later immediately to resolve CVE-2026-55074.
- Audit existing Ansible playbooks for 'copy', 'template', or 'fetch' tasks that interact with untrusted or multi-user jails.
- Monitor host-side logs for unexpected 'mkdir' or 'mv' process executions originating from the Ansible controller or the user running the Ansible automation.
- Review filesystems mounted within jails for unauthorized symbolic links in directories frequently targeted by automation tasks.
