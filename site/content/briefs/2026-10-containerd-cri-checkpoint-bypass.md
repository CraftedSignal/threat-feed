---
title: Containerd CRI Checkpoint Restore Privilege Escalation
slug: 2026-10-containerd-cri-checkpoint-bypass
description: A vulnerability in the containerd CRI implementation (CVE-2026-95837) allows untrusted container checkpoints to bypass configured security contexts, enabling privilege escalation to root.
date: "2026-10-15T22:23:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:containerd:containerd:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - containerd
  - cve-2026-95837
vendors:
  - containerd
products:
  - containerd (2.1.0 to <2.2.7, 2.3.0 to <2.3.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in containerd's CRI implementation allows a container restored from an untrusted checkpoint via the CreateContainer API to bypass the destination security context and execute with elevated privileges.
    confidence_band: high
cves:
  - id: CVE-2026-95837
    cvss: 7.8
    epss: 0.00106
references:
  - https://github.com/advisories/GHSA-p7v4-vr35-mj6f
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95837
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade containerd to 2.2.7, 2.3.4, or 2.4.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-95837 remediation
  mitigation_plan:
    - priority: immediate
      action: Restart all containers restored via checkpoint API
      owner: IT Operations
      addresses: CVE-2026-95837
      evidence: Source explicitly advises to stop, delete, and recreate containers restored from untrusted checkpoints.
---

CVE-2026-95837 describes a critical flaw in the containerd CRI plugin where container restoration from untrusted checkpoints via the CreateContainer API ignores destination security contexts. Instead of enforcing the security policies defined by the orchestrator, containerd restores sensitive process state - including Linux capabilities, UIDs/GIDs, no_new_privs, and seccomp filters - directly from the checkpoint archive. This allows an attacker to manipulate the checkpoint image to execute code with elevated privileges, effectively bypassing isolation mechanisms. 

The vulnerability is particularly dangerous because containerd's internal status reporting inaccurately reflects the requested (restricted) configuration rather than the actual (elevated) state of the restored process, misleading security monitoring systems. Affected versions include containerd v2.1.0 through v2.2.6, and v2.3.0 through v2.3.3. This feature is disabled by default in fixed versions 2.2.7 and 2.3.4, and entirely removed in 2.4.0.

## Impact

Successful exploitation allows a containerized process to escape restrictive security policies and execute as root with full Linux capabilities. This could lead to container escapes, host-level compromise, or the circumvention of organization-wide security posture. Impact is limited to environments utilizing containerd with CRI checkpoint restore enabled.

## Recommendation

- Upgrade containerd to version 2.2.7, 2.3.4, or 2.4.0 immediately to resolve CVE-2026-95837.
- Terminate and delete any existing running containers that were restored using the CRI checkpoint restore feature to ensure no persistence of compromised states.
- Implement admission controllers to scan container images and reject any images containing CRIU checkpoint data unless verified as trusted.
- Restrict access to the CreateContainer API to trusted administrative users only until the patch is applied.
