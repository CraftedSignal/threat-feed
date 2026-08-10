---
title: Local Privilege Escalation in libvirt via Symlink Following (CVE-2026-63622)
slug: 2026-08-libvirt-symlink-priv-esc
description: A local privilege escalation vulnerability in libvirt allows a confined swtpm process to trick the libvirt daemon into changing file ownership through symlink following, potentially granting root-level file access.
date: "2026-08-10T21:40:21Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Libvirt
products:
  - libvirt
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: By planting a symbolic link within the swtpm state directory, the attacker could trick the root-level libvirt daemon into changing the ownership of an arbitrary file to the swtpm user.
    confidence_band: high
cves:
  - id: CVE-2026-63622
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63622
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch libvirt on all virtualization hosts.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-63622 remediation
  mitigation_plan:
    - priority: immediate
      action: Enforce strict MAC (AppArmor/SELinux) policies on swtpm binaries.
      owner: IT Operations
      addresses: CVE-2026-63622
      evidence: Vulnerability involves sandbox breakout via file ownership manipulation.
---

A vulnerability identified as CVE-2026-63622 exists within the libvirt management library, specifically involving the `virFileChownFiles()` function. The flaw enables a local attacker, operating under the constrained `swtpm` user context, to perform unauthorized file ownership changes. By creating malicious symbolic links within the `swtpm` state directory, an attacker can influence the libvirt daemon - which runs with root privileges - to perform a chown operation on arbitrary files on the host system. This mechanism effectively breaks the sandbox isolation, allowing the `swtpm` process to gain ownership of system files, thereby facilitating privilege escalation to root-level file access. This vulnerability is significant for environments leveraging virtual machine TPM emulation.

## Impact

Successful exploitation allows a low-privileged `swtpm` process to gain ownership over arbitrary files on the host filesystem. This impact is critical in multi-tenant environments or systems relying on libvirt for virtualization security, as it provides a pathway for the attacker to manipulate security-sensitive files, bypass access controls, or escalate privileges to full root access depending on the target file selected for ownership transition.

## Recommendation

- Apply vendor-supplied patches for the libvirt library immediately to address CVE-2026-63622.
- Audit the `swtpm` state directory locations on virtualization hosts for unusual symbolic link creations.
- Implement stricter SELinux or AppArmor profiles for the `swtpm` process to restrict file system access outside of designated state directories.
- Monitor for unexpected calls to `chown` or `fchown` initiated by the `libvirtd` process.
