---
title: Gitea act_runner Container Escape via Unsanitized Workflow Options
slug: 2026-10-gitea-runner-container-escape
description: An improper sanitization vulnerability in Gitea act_runner allows attackers to inject malicious Docker CLI flags into workflow container configurations, leading to full container escape and root-level command execution on the host.
date: "2026-10-03T04:50:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:gitea:gitea-runner:*:*:*:*:*:*:*:*
vendors:
  - Gitea
products:
  - gitea-runner (< 1.0.9-0.20260731160927-34bfa1915022)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: An attacker can enter host PID, IPC, and mount namespaces and execute arbitrary commands as root on the runner host.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attacker executes arbitrary commands as root on the runner host.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-x4q3-gcj3-m6cf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73802
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Gitea act_runner to 1.0.9-0.20260731160927-34bfa1915022 or later.
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies this version as the fix for CVE-2026-73802.
  mitigation_plan:
    - priority: immediate
      action: Identify and block workflows utilizing container.options to configure host namespaces or capability expansion.
      owner: Security Engineering
      addresses: CVE-2026-73802
      evidence: 'Source provides list of flags to strip: --pid=host, --ipc=host, --cap-add, etc.'
---

The Gitea act_runner (CVE-2026-73802) fails to properly sanitize the `container.options` field in workflow YAML files when privileged mode is disabled. While the runner forces the `Privileged` flag to false, it does not validate or strip other security-sensitive Docker HostConfig parameters. An attacker with the ability to trigger a workflow on a shared runner can supply custom Docker flags, such as `--pid=host`, `--ipc=host`, and various security profile overrides (e.g., `seccomp=unconfined`). These flags are merged into the container configuration, granting the job container broad access to the runner host's namespaces and resources. This vulnerability allows an attacker to escape the container, execute commands as root on the host, access host secrets, and pivot to other jobs running on the same infrastructure. The vulnerability affects versions of `gitea-runner` prior to 1.0.9-0.20260731160927-34bfa1915022.

## Attack Chain

1. Attacker creates or modifies a workflow YAML file in a repository that triggers a Gitea act_runner.
2. Attacker defines a `container` block in the job specification including a malicious `options` field.
3. Attacker populates the `options` field with escape-enabling flags like `--pid=host`, `--ipc=host`, and `--cap-add=ALL`.
4. The Gitea runner parses the workflow and executes `mergeContainerConfigs()`, which incorporates these flags into the Docker HostConfig.
5. The runner initiates a Docker container using the malicious HostConfig, bypassing security constraints despite `privileged` mode being set to false.
6. The workflow job starts, and the attacker utilizes tools like `nsenter` to break out of the container namespace and gain shell access.
7. Attacker executes arbitrary commands with root privileges on the runner host to exfiltrate secrets or pivot to adjacent tasks.

## Impact

Successful exploitation results in full compromise of the runner host. In shared hosting environments, this allows attackers to access secrets, environment variables, and deployment credentials belonging to other users or jobs, and potentially penetrate internal build infrastructure reachable from the host.

## Recommendation

1. Upgrade Gitea act_runner to version 1.0.9-0.20260731160927-34bfa1915022 or later immediately to patch CVE-2026-73802.
2. Audit existing Gitea workflow files for usage of `container.options` that reference namespace or security capability flags.
3. Implement strict input validation on workflow runners to deny configurations that include `--pid=host`, `--ipc=host`, `--uts=host`, `--network=host`, or security-critical `seccomp`/`apparmor` overrides.
