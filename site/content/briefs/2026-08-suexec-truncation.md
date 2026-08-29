---
title: CVE-2026-82457 Privilege Escalation in su-exec
slug: 2026-08-suexec-truncation
description: The su-exec utility up to version 0.3 suffers from integer truncation during user identifier parsing, allowing attackers to escalate privileges to root.
date: "2026-08-29T15:40:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:su-exec_project:su-exec:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - vulnerability
  - linux
products:
  - su-exec (<= 0.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can supply large numeric identifiers that truncate to root's identifier, causing su-exec to execute target programs with root privileges instead of intended unprivileged accounts.
    confidence_band: high
cves:
  - id: CVE-2026-82457
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82457
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory all container images containing su-exec <= 0.3
      owner: Security Engineering
      due: 48h
      evidence: CVE-2026-82457 affects su-exec up to 0.3
  mitigation_plan:
    - priority: immediate
      action: Transition container entrypoints away from su-exec until a patched version is deployed
      owner: IT Operations
      addresses: CVE-2026-82457
      evidence: NVD vulnerability report
---

The su-exec utility, a tool commonly used to step down from root privileges to a specific unprivileged user in containerized environments, contains a critical integer overflow and truncation vulnerability (CVE-2026-82457). The software uses the strtol function to parse user and group identifiers from command-line arguments but fails to validate the resulting numeric range before casting these values to uid_t and gid_t types. 

If an attacker provides an extremely large numeric identifier as input, the underlying system cast causes the value to truncate, wrapping around to zero, which corresponds to the root user identifier. Consequently, su-exec may fail to transition to the intended unprivileged user and instead execute the target command with full root privileges. This vulnerability impacts all versions of su-exec up to and including 0.3, posing a significant risk in environments where this utility is used as a security boundary for container entrypoints.

## Impact

The successful exploitation of CVE-2026-82457 results in an attacker gaining unauthorized root-level access on the host or container, bypassing intended access controls. This vulnerability primarily affects Linux-based container environments that utilize su-exec to manage process user privileges. If exploited, an attacker can maintain persistent root access, modify system files, or move laterally within the containerized environment.

## Recommendation

- Identify all instances of su-exec 0.3 or older within the environment, particularly within container images and orchestration configurations.
- Patch or upgrade the su-exec dependency to a version that addresses CVE-2026-82457 as soon as a fix is available from the maintainer.
- Audit container entrypoint scripts that invoke su-exec to ensure they do not accept untrusted user-supplied input for UID/GID arguments.
- Enforce the use of non-root users at the container orchestration level (e.g., Kubernetes SecurityContext) to minimize the impact of successful privilege escalation.
