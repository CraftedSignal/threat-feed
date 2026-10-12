---
title: Incorrect Permissions in Edgeless Systems Contrast
slug: 2026-10-edgeless-contrast-vuln
description: Edgeless Systems Contrast versions 1.8.0 through 1.24.0 contain a world-writable containerd configuration file vulnerability, allowing local unprivileged users to achieve privilege escalation.
date: "2026-10-12T18:37:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:edgelesssystems:contrast:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - vulnerability
vendors:
  - Edgeless Systems
products:
  - Contrast (< 1.24.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Local unprivileged users on the node can modify the containerd config, for example overwriting the runc location, to escalate privileges.
    confidence_band: high
cves:
  - id: CVE-2026-109358
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109358
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Edgeless Systems Contrast to 1.24.1 or later
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-109358 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Manually restrict file permissions on the containerd config file to 0600
      owner: IT Operations
      addresses: CVE-2026-109358
      evidence: NVD vulnerability details regarding incorrect 0666 permissions
---

Edgeless Systems Contrast versions 1.8.0 through 1.24.0 are affected by a security vulnerability regarding improper file permissions. The node installer for the platform creates the containerd configuration file with world-writable (0666) permissions on the underlying Linux host. This flaw allows any local unprivileged user to modify the configuration file. By altering parameters within the containerd configuration, such as redirecting the path of the runc binary to a malicious executable, an attacker can cause the service to execute arbitrary code with elevated privileges, effectively resulting in local privilege escalation. This vulnerability poses a high risk in multi-tenant environments or systems where untrusted users have local shell access to the node.

## Impact

Successful exploitation of this vulnerability allows an unprivileged local user to gain root-level execution on the affected node. This can lead to full system compromise, data theft, and persistence, specifically impacting environments running Edgeless Systems Contrast for secure container orchestration.

## Recommendation

Prioritized, concrete actions for detection engineering and system administration teams:

- Upgrade Edgeless Systems Contrast to version 1.24.1 or later to resolve the underlying installer behavior and ensure correct file permissions (0600 or 0644).
- Audit existing deployments of Contrast for world-writable configuration files in the containerd path by checking file permissions for /etc/containerd/config.toml (or equivalent).
- Use system monitoring to detect unauthorized modifications to containerd configuration files by monitoring file integrity for the configuration directory.
