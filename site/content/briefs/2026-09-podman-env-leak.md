---
title: Podman Environment Variable Leak via Malformed Container Images
slug: 2026-09-podman-env-leak
description: A vulnerability in Podman allows malicious container images containing malformed environment variables to exfiltrate host environment variables into the container environment at runtime.
date: "2026-09-24T20:05:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:podman_project:podman:*:*:*:*:*:*:*:*
  - cpe:2.3:a:podman_project:podman:6.0.0:rc1:*:*:*:*:*:*
tags:
  - container-security
  - credential-theft
vendors:
  - Red Hat
products:
  - Podman (< 5.8.4, < 6.0.0, <= 4.9.5, <= 3.4.7, <= 2.2.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: A malicious image can exfiltrate all podman environment variables that are set in the session from where the container is launched.
    confidence_band: high
cves:
  - id: CVE-2026-57231
    cvss: 7.5
    epss: 0.00312
references:
  - https://github.com/advisories/GHSA-4hq8-gpf5-8p68
  - https://github.com/podman-container-tools/podman/commit/6c431b73dbf8e4b20b778644d7a80caebdb75050
action_plan:
  priority: elevated
  owners:
    - Security Engineering
  immediate_actions:
    - action: Upgrade Podman to v5.8.4 or v6.0.0 based on the installed version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-57231 fix requirement
  mitigation_plan:
    - priority: immediate
      action: Implement a CI/CD gate that runs 'podman image inspect' to flag images with malformed environment variables
      owner: DevOps
      addresses: CVE-2026-57231
      evidence: Workaround documentation in GHSA-4hq8-gpf5-8p68
---

Podman contains a high-severity vulnerability (CVE-2026-57231) that enables the unauthorized exfiltration of host environment variables into a running container. The issue arises from flawed parsing logic within the container image configuration; specifically, if an image defines environment variables without an accompanying value, or utilizes wildcard characters such as an asterisk, Podman improperly interprets these entries.

By design, the Podman `--env` flag is intended to map host variables to a container. Due to the reuse of this parsing logic for image configuration, an attacker can craft a container image that forces the container engine to mirror sensitive host-side environment variables - such as API keys, database credentials, or tokens - directly into the container's process space upon execution. This vulnerability affects multiple versions of Podman across the v2 through v6 branches. Defenders should prioritize upgrading to patched versions or implementing strict image validation processes.

## Impact

Successful exploitation allows an attacker to gain unauthorized access to sensitive host environment variables. In cloud or CI/CD environments where containers are frequently executed, this could lead to the exposure of credentials, service account tokens, or environment configuration secrets, potentially facilitating lateral movement or privilege escalation within the host or broader infrastructure.

## Recommendation

- Upgrade Podman to a secure version as specified in the advisory: v5.8.4, v6.0.0, or higher depending on the deployment branch.
- Prior to execution, audit untrusted container images using the command: `podman image inspect --format '{{.Config.Env}}' <image>`. Identify and block images containing environment variables that lack a key-value assignment (i.e., variables not following the `key=value` format).
- Enforce strict policies regarding the ingestion of images from public or untrusted container registries.
