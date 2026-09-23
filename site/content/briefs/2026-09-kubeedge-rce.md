---
title: Command Injection Vulnerability in KubeEdge NodeUpgradeJob
slug: 2026-09-kubeedge-rce
description: An authenticated remote code execution vulnerability (CVE-2026-62371) in the KubeEdge v1alpha2 API allows attackers to inject shell commands via the NodeUpgradeJob resource.
date: "2026-09-23T01:55:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kubeedge:kubeedge:*:*:*:*:*:*:*:*
vendors:
  - KubeEdge
products:
  - KubeEdge (v1.21.2, v1.22.2, v1.23.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The KubeEdge NodeUpgradeJob handler constructed the keadm upgrade edge command by concatenating the user-controlled spec.version and spec.image fields into a shell command.
    confidence_band: high
cves:
  - id: CVE-2026-62371
    cvss: 8.8
references:
  - https://github.com/advisories/GHSA-5jpj-293f-rhvj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62371
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade KubeEdge to versions 1.21.2, 1.22.2, or 1.23.1
      owner: IT Operations
      due: 24h
      evidence: Fixed versions provided in GHSA-5jpj-293f-rhvj
  mitigation_plan:
    - priority: immediate
      action: Restrict permissions to create or update NodeUpgradeJob resources to trusted administrators
      owner: IT Operations
      addresses: CVE-2026-62371
      evidence: Workaround provided in GHSA-5jpj-293f-rhvj
---

KubeEdge versions within the 1.21.x, 1.22.x, and 1.23.x release branches contain a command injection vulnerability (CVE-2026-62371) affecting the NodeUpgradeJob resource handler within the v1alpha2 API. The vulnerability arises because the controller concatenates user-supplied values from the 'spec.version' and 'spec.image' fields directly into a shell string used to invoke 'keadm upgrade edge'. An attacker with the ability to create or update NodeUpgradeJob resources can inject shell metacharacters into these fields, resulting in arbitrary code execution on the target edge node with the privileges of the KubeEdge upgrade process. This issue represents a significant risk for deployments where API access is shared with untrusted entities, as it allows for container escape or host-level compromise of edge computing infrastructure.

## Attack Chain

1. An attacker gains authenticated access to the KubeEdge cluster with permissions to manage NodeUpgradeJob resources.
2. The attacker crafts a malicious payload using shell metacharacters (e.g., ';', '&&', or '$()').
3. The attacker submits an update or create request to the v1alpha2 API for a NodeUpgradeJob resource.
4. The malicious shell metacharacters are embedded within the 'spec.version' or 'spec.image' YAML fields.
5. The KubeEdge controller processes the resource and dynamically builds the upgrade command using shell-based concatenation.
6. The system executes the resulting command string via the OS shell, triggering the payload.
7. The injected code executes on the target edge node, granting the attacker arbitrary command execution capabilities.

## Impact

Successful exploitation of CVE-2026-62371 grants authenticated attackers the ability to execute arbitrary commands on edge nodes. Given that edge nodes often operate in distributed environments with access to local hardware or sensitive data, this can lead to total node compromise, persistent backdooring of edge infrastructure, and lateral movement into the broader KubeEdge ecosystem. The vulnerability impacts KubeEdge deployments versions 1.12.0 through 1.23.0, excluding specific patched releases.

## Recommendation

1. Upgrade KubeEdge instances to version 1.21.2, 1.22.2, or 1.23.1 to address CVE-2026-62371.
2. Implement strict Kubernetes Role-Based Access Control (RBAC) to limit the ability to create or update NodeUpgradeJob resources to authorized administrators only.
3. Audit cluster logs for unusual modifications to NodeUpgradeJob objects that include unexpected shell special characters in version or image fields.
